# vt_search.py  — requests版（逐次リアルタイム更新・バックグラウンド実行）

import os
import re
import csv
import time
import sys
import threading
import queue
import requests
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Dict, Any, List

# =========================
# 設定
# =========================
CONFIG_FILE = "vt_keys.txt"   # プログラム直下。1行1キー、行中の # 以降はコメント可
VT_SEARCH_ENDPOINT = "https://www.virustotal.com/api/v3/search?query={q}"
VENDOR_KEYS = ["Microsoft", "Kaspersky", "Symantec", "TrendMicro", "BitDefender", "ESET"]

# 入力フォームの区切り：改行 / カンマ（,，、）/ セミコロン / タブ / CR
SEP_PATTERN = re.compile(r"[,\uFF0C\u3001;\t\r\n]+")

# VT Public API の想定：429 が来たら 60 秒待つ
RETRY_SLEEP_SECONDS_ON_429 = 90
REQUEST_TIMEOUT = (10, 30)  # (connect, read) seconds


# =========================
# API キー読み込み・正規化
# =========================
def _strip_bom(s: str) -> str:
    return s.lstrip("\ufeff")  # UTF-8 BOM を除去

def _strip_inline_comment(s: str) -> str:
    pos = s.find("#")
    return s if pos < 0 else s[:pos]

def _strip_weird_spaces(s: str) -> str:
    return "".join(ch for ch in s if ch not in ("\u3000", "\u00A0", "\u200B", "\uFEFF"))

def _is_ascii(s: str) -> bool:
    try:
        s.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False

def _looks_like_vt_key(s: str) -> bool:
    # VT API key は 64 桁英数字
    return bool(re.fullmatch(r"[A-Za-z0-9]{64}", s))
    
def _looks_like_username(s: str) -> bool:
    """
    VTのユーザ名に使われがちな文字のみ許可（英数・アンダースコア・ハイフン・ドット）。
    先頭末尾のドット/ハイフンは避ける程度の緩めチェック。
    """
    if not s or len(s) > 64:
        return False
    if not re.fullmatch(r"[A-Za-z0-9._-]+", s):
        return False
    if s[0] in ".-" or s[-1] in ".-":
        return False
    return True

def load_api_keys(config_path: str = CONFIG_FILE) -> List[dict]:
    """
    vt_keys.txt から複数アカウントを読み込む。
    - 行形式:   username,apikey   または   apikey
    - 前処理:   BOM除去 / #以降コメント除去 / 全角・不可視空白除去 / strip
    - 検証:     ASCIIのみ / APIキーは64桁英数字 / ユーザ名は _looks_like_username
    - 重複:     同一APIキーは除外（先勝ち）
    戻り値: [{ "username": str, "key": str }, ...]
    """
    if not os.path.exists(config_path):
        raise RuntimeError(f"設定ファイルが見つかりません: {config_path}")

    accounts: List[dict] = []
    seen_keys = set()

    with open(config_path, "r", encoding="utf-8") as f:
        for raw in f:
            line = _strip_bom(raw.strip())
            if not line:
                continue
            line = _strip_inline_comment(line).strip()
            if not line:
                continue
            line = _strip_weird_spaces(line).strip()
            if not line:
                continue

            # 形式判定：username,apikey か apikey 単独
            username = "unknown"
            key = line
            if "," in line:
                u, k = line.split(",", 1)
                username, key = u.strip(), k.strip()

            # 検証（ASCII）
            if not _is_ascii(key) or (username != "unknown" and not _is_ascii(username)):
                # 非ASCII混入はスキップ
                continue

            # APIキー検証（64桁英数字）
            if not _looks_like_vt_key(key):
                continue

            # ユーザ名検証（username,apikey 形式のときのみ厳密チェック）
            if username != "unknown" and not _looks_like_username(username):
                # 形式が怪しければ unknown にフォールバック
                username = "unknown"

            if key in seen_keys:
                continue
            seen_keys.add(key)
            accounts.append({"username": username, "key": key})

    if not accounts:
        raise RuntimeError(
            f"{config_path} に有効なエントリが見つかりません。\n"
            "例) user1,aaaaaaaa...(64桁)  または  aaaaaaaa...(64桁)"
        )
    return accounts

# グローバル格納（回転用）
_API_ACCOUNTS = None
_API_IDX = 0

def ensure_keys_loaded():
    """初回ロード or 再ロードで _API_ACCOUNTS を準備"""
    global _API_ACCOUNTS, _API_IDX
    if _API_ACCOUNTS is None:
        _API_ACCOUNTS = load_api_keys(CONFIG_FILE)
        _API_IDX = 0

def get_next_api_key() -> str:
    """既存コード互換：キーだけ返す（内部はアカウント配列を回す）"""
    global _API_IDX
    ensure_keys_loaded()
    key = _API_ACCOUNTS[_API_IDX]["key"]
    _API_IDX = (_API_IDX + 1) % len(_API_ACCOUNTS)
    return key

def api_keys_count() -> int:
    ensure_keys_loaded()
    return len(_API_ACCOUNTS)

# 便利：必要なら“アカウント丸ごと”を取りたいときに使う
def get_account(idx: int = None) -> dict:
    """
    idx 指定: そのアカウントを返す
    指定なし: 現在の回転位置のアカウントを参照（読み取り用途）
    """
    ensure_keys_loaded()
    if idx is None:
        i = (_API_IDX - 1) % len(_API_ACCOUNTS)  # 直近で使った位置
        return _API_ACCOUNTS[i]
    return _API_ACCOUNTS[idx % len(_API_ACCOUNTS)]

def vt_get_usage_by_username(username: str, api_key: str, timeout=(10, 30)):
    """
    VT 使用状況（overall_quotas）を取得。スキーマ差異に耐性あり。
    戻り値例:
      {
        "minutely": (used, allowed)  # 分が取れないときは None
        "hourly":   (used, allowed),
        "daily":    (used, allowed),
        "minute_cap_from_hour": 4    # 分の上限が不明のときだけ入る（例: 240/60=4）
      }
      or {"error": "..."}
    """
    url = f"https://www.virustotal.com/api/v3/users/{username}/overall_quotas"
    try:
        r = requests.get(url, headers={"x-apikey": api_key}, timeout=timeout)
    except requests.RequestException as e:
        return {"error": f"request error: {e}"}

    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}: {r.text}"}

    try:
        root = r.json()
        data = root.get("data", {}) or {}

        # ---- 優先: 新スキーマ data.api_requests.minute.user ----
        api_requests = data.get("api_requests") or {}
        minute_user = (((api_requests.get("minute") or {}).get("user")) or None)
        hour_user   = (((api_requests.get("hour")   or {}).get("user")) or None)
        day_user    = (((api_requests.get("day")    or {}).get("user")) or None)

        # ---- 旧スキーマ: data.api_requests_minutely / hourly / daily ----
        if minute_user is None and "api_requests_minutely" in data:
            minute_user = (data.get("api_requests_minutely", {}) or {}).get("user")
        if hour_user is None and "api_requests_hourly" in data:
            hour_user   = (data.get("api_requests_hourly", {})   or {}).get("user")
        if day_user is None and "api_requests_daily" in data:
            day_user    = (data.get("api_requests_daily", {})    or {}).get("user")

        # 値の整形（存在すれば取り出す）
        def pair(u):
            if not isinstance(u, dict): return None
            return int(u.get("used", 0)), int(u.get("allowed", 0))

        minute_pair = pair(minute_user)  # ない場合は None
        hour_pair   = pair(hour_user)    # 無ければ None
        day_pair    = pair(day_user)

        result = {
            "minutely": minute_pair,
            "hourly":   hour_pair,
            "daily":    day_pair,
        }

        # 分が無いときは「時間上限/60 ≈ 分上限」を補足情報として付与
        if minute_pair is None and hour_pair and hour_pair[1] > 0:
            result["minute_cap_from_hour"] = max(1, hour_pair[1] // 60)

        return result

    except Exception as e:
        return {"error": f"parse error: {e}"}

# =========================
# VT クエリ（requests）
# =========================
def pick_vendor_verdicts(results: Dict[str, Any]) -> Dict[str, str]:
    """
    主要ベンダーの表示を 'malicious' ではなく検出名(result)優先に。
    result が無い場合は category をフォールバック。どちらも無ければ 'n/a'。
    """
    out = {}
    for want in VENDOR_KEYS:
        shown = "n/a"
        for engine_name, v in results.items():
            if engine_name.lower().startswith(want.lower()):
                if isinstance(v, dict):
                    name = v.get("result")
                    cat = v.get("category")
                    if name:
                        shown = name
                    elif cat:
                        shown = cat
                    else:
                        shown = "n/a"
                else:
                    shown = str(v) if v is not None else "n/a"
                break
        out[want] = shown
    return out

def vt_query_one(ioc: str) -> Dict[str, Any]:
    """
    VT /search を使って 1 IOC の最新解析をざっくり取得。
    429 の場合は呼び出し側で待って再試行する設計。
    """
    url = VT_SEARCH_ENDPOINT.format(q=requests.utils.quote(ioc))
    key = get_next_api_key()
    headers = {"x-apikey": key}

    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as e:
        return {"indicator": ioc, "error": f"request error: {e}"}

    if resp.status_code == 429:
        return {"indicator": ioc, "error": "rate limit exceeded"}

    if resp.status_code != 200:
        return {"indicator": ioc, "error": f"HTTP {resp.status_code}"}

    try:
        data = resp.json()
    except ValueError:
        return {"indicator": ioc, "error": "invalid JSON from VT"}

    arr = data.get("data") or []
    if not arr:
        return {"indicator": ioc, "error": "no result"}

    item = arr[0]
    attrs = item.get("attributes", {}) or {}
    stats = attrs.get("last_analysis_stats", {}) or {}
    results = attrs.get("last_analysis_results", {}) or {}

    total = sum(int(stats.get(k, 0)) for k in [
        "harmless","malicious","suspicious","undetected","timeout",
        "confirmed-timeout","failure","type-unsupported"
    ])
    ratio = f"{int(stats.get('malicious', 0))}/{total if total else 0}"

    majors = pick_vendor_verdicts(results)

    return {
        "indicator": ioc,
        "detection_ratio": ratio,
        "stats": stats,
        "major_vendors": majors,
        "error": ""
    }


# =========================
# 入力ユーティリティ
# =========================
def parse_ioc_text(text: str) -> List[str]:
    tokens = [t.strip() for t in SEP_PATTERN.split(text)]
    items = [t for t in tokens if t and not t.startswith("#")]
    # 重複除去（順序保持）
    seen, out = set(), []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def read_iocs_from_csv(path: str) -> List[str]:
    cells: List[str] = []
    with open(path, newline="", encoding="utf-8") as f:
        try:
            reader = csv.reader(f)
            for row in reader:
                for c in row:
                    if c and c.strip():
                        cells.append(c.strip())
        except csv.Error:
            f.seek(0)
            return parse_ioc_text(f.read())
    return parse_ioc_text("\n".join(cells))


# =========================
# GUI（リアルタイム更新版）
# =========================
class VTApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VirusTotal Multi-Checker")
        self.geometry("1280x780")

        # メニュー
        menubar = tk.Menu(self)
        filem = tk.Menu(menubar, tearoff=0)
        filem.add_command(label="CSV から読み込み…", command=self.menu_load_csv)
        filem.add_command(label="結果を CSV へ保存…", command=self.menu_save_csv)
        filem.add_separator()
        filem.add_command(label="終了", command=self.destroy)
        menubar.add_cascade(label="ファイル", menu=filem)

        keym = tk.Menu(menubar, tearoff=0)
        keym.add_command(label="（再）キー読み込み（固定ファイル）", command=self.reload_keys_fixed)
        keym.add_command(label="別ファイルから読み込み…", command=self.menu_load_keys_any)
        keym.add_command(label="現在のキー数を表示", command=self.show_key_count)
        keym.add_command(label="使用状況を更新", command=self.update_usage_status)
        menubar.add_cascade(label="APIキー", menu=keym)

        self.config(menu=menubar)

        # 上段：入力
        top = ttk.Frame(self); top.pack(fill="x", padx=8, pady=6)
        ttk.Label(top, text=f"IOC 入力フォーム（改行 / カンマ / タブ / セミコロン 区切り） / キー: '{CONFIG_FILE}'").pack(anchor="w")
        self.text = tk.Text(top, height=6); self.text.pack(fill="x")

        btns = ttk.Frame(top); btns.pack(fill="x", pady=4)
        self.btn_add = ttk.Button(btns, text="表に追加", command=self.add_from_text)
        self.btn_add.pack(side="left", padx=(0,6))
        self.btn_clear = ttk.Button(btns, text="表をクリア", command=self.clear_table)
        self.btn_clear.pack(side="left")
        self.btn_run = ttk.Button(btns, text="スキャン開始", command=self.run_scan)
        self.btn_run.pack(side="right")

        # 中段：結果テーブル
        mid = ttk.Frame(self); mid.pack(fill="both", expand=True, padx=8, pady=6)

        cols = (
            "indicator","detection_ratio",
            "vendor.Microsoft","vendor.Kaspersky","vendor.Symantec",
            "vendor.TrendMicro","vendor.BitDefender","vendor.ESET",
            "error",
            "stats.malicious","stats.suspicious","stats.harmless",
            "stats.undetected","stats.timeout","stats.confirmed-timeout",
            "stats.failure","stats.type-unsupported"
        )
        self.tree = ttk.Treeview(mid, columns=cols, show="headings", height=16)

        # error 行は赤字
        self.tree.tag_configure("error", foreground="red")

        for c in cols:
            heading_text = c.split(".", 1)[1] if "." in c else c
            self.tree.heading(c, text=heading_text)
            self.tree.column(c, width=120 if not c.startswith("stats.") else 110, anchor="w")
        self.tree.column("indicator", width=320)
        self.tree.column("error", width=360)

        ybar = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        xbar = ttk.Scrollbar(mid, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=ybar.set, xscroll=xbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ybar.grid(row=0, column=1, sticky="ns")
        xbar.grid(row=1, column=0, sticky="ew")
        mid.rowconfigure(0, weight=1); mid.columnconfigure(0, weight=1)

        # 下段：ログ
        low = ttk.Frame(self); low.pack(fill="both", expand=True, padx=8, pady=(0,8))
        ttk.Label(low, text="ログ").pack(anchor="w")
        self.log = tk.Text(low, height=8, state="normal")
        self.log.pack(fill="both", expand=True)
        status = ttk.Frame(self); status.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="Usage: 未取得")
        self.status_label = ttk.Label(status, textvariable=self.status_var, anchor="w")
        self.status_label.pack(fill="x")

        # 状態
        self.row_index_by_indicator: Dict[str, str] = {}
        self.progress_q: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self.scanning = False

        # 起動時にキーをロード（失敗時はダイアログ）
        try:
            ensure_keys_loaded()
        except Exception as e:
            messagebox.showwarning("APIキー読込エラー", str(e))
        self.after(200, self.update_usage_status)

    # ----- メニュー動作 -----
    def update_usage_status(self):
	    try:
	        ensure_keys_loaded()
	        accounts = _API_ACCOUNTS
	    except Exception as e:
	        self.status_var.set(f"Usage: 読込エラー ({e})")
	        return

	    texts = []
	    for acc in accounts:
	        u = (acc.get("username") or "unknown").strip()
	        k = acc.get("key")
	        if not k:
	            continue
	        if u == "unknown":
	            texts.append("[unknown] username が無いので使用量を取得できません")
	            continue

	        usage = vt_get_usage_by_username(u, k)
	        if "error" in usage:
	            texts.append(f"[{u}] error: {usage['error']}")
	            continue

	        mi = usage.get("minutely")
	        ho = usage.get("hourly")
	        da = usage.get("daily")
	        cap = usage.get("minute_cap_from_hour")

	        # 時・日が無いことは通常ないが念のためガード
	        ho_txt = f"{ho[0]}/{ho[1]} hr" if ho else "hr: N/A"
	        da_txt = f"{da[0]}/{da[1]} day" if da else "day: N/A"

	        if mi:
	            mi_txt = f"{mi[0]}/{mi[1]} min"
	        elif cap:
	            mi_txt = f"~{cap}/min cap"
	        else:
	            mi_txt = "min: N/A"

	        texts.append(f"[{u}] {mi_txt} | {ho_txt} | {da_txt}")

	    self.status_var.set("  •  ".join(texts) if texts else "Usage: キーが見つかりません")

	    
    def menu_load_csv(self):
        path = filedialog.askopenfilename(title="CSV から読み込み",
                                          filetypes=[("CSV", "*.csv"), ("すべてのファイル", "*.*")])
        if not path: return
        try:
            iocs = read_iocs_from_csv(path)
            if not iocs:
                messagebox.showinfo("読み込み", "IOC が見つかりませんでした。"); return
            self.text.delete("1.0","end")
            self.text.insert("end", "\n".join(iocs))
            self.log_print(f"CSV から {len(iocs)} 件を読み込み: {path}")
        except Exception as e:
            messagebox.showerror("読み込みエラー", str(e))

    def menu_save_csv(self):
        path = filedialog.asksaveasfilename(title="結果を CSV へ保存",
                                            defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path: return
        try:
            cols = self.tree["columns"]
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(cols)
                for iid in self.tree.get_children(""):
                    writer.writerow(self.tree.item(iid, "values"))
            self.log_print(f"結果を保存: {path}")
            messagebox.showinfo("保存完了", f"{path} に保存しました")
        except Exception as e:
            messagebox.showerror("保存エラー", str(e))

    def reload_keys_fixed(self):
        global _API_KEYS, _API_IDX
        try:
            _API_KEYS = load_api_keys(CONFIG_FILE)
            _API_IDX = 0
            self.log_print(f"固定ファイル '{CONFIG_FILE}' から APIキーを {len(_API_KEYS)} 件読み込み。")
        except Exception as e:
            messagebox.showerror("キー読み込みエラー", str(e))

    def menu_load_keys_any(self):
        global _API_KEYS, _API_IDX
        path = filedialog.askopenfilename(title="APIキーをファイルから読み込み",
                                          filetypes=[("Text", "*.txt"), ("すべてのファイル", "*.*")])
        if not path: return
        try:
            _API_KEYS = load_api_keys(path)
            _API_IDX = 0
            self.log_print(f"APIキーを {len(_API_KEYS)} 件読み込み: {path}")
        except Exception as e:
            messagebox.showerror("キー読み込みエラー", str(e))

    def show_key_count(self):
        try:
            n = api_keys_count()
            messagebox.showinfo("APIキー", f"読み込み済みキー数: {n}")
        except Exception as e:
            messagebox.showerror("情報", str(e))

    # ----- 入力・表処理 -----
    def add_from_text(self):
        raw = self.text.get("1.0", "end")
        iocs = parse_ioc_text(raw)
        if not iocs:
            messagebox.showinfo("追加", "追加する IOC がありません。"); return
        added = 0
        for ioc in iocs:
            if ioc in self.row_index_by_indicator:  # 重複スキップ
                continue
            iid = self.tree.insert("", "end", values=self._blank_row(ioc))
            self.row_index_by_indicator[ioc] = iid
            added += 1
        self.log_print(f"{added} 件を表に追加（重複除去済み）。")

    def clear_table(self):
        self.tree.delete(*self.tree.get_children(""))
        self.row_index_by_indicator.clear()
        self.log_delete_all()
        self.log_print("表とログをクリアしました。")

    def _blank_row(self, indicator: str):
        base = {
            "indicator": indicator,
            "detection_ratio": "",
            "vendor.Microsoft": "", "vendor.Kaspersky":"", "vendor.Symantec":"",
            "vendor.TrendMicro":"", "vendor.BitDefender":"", "vendor.ESET":"",
            "error":"",
            "stats.malicious":"", "stats.suspicious":"", "stats.harmless":"",
            "stats.undetected":"", "stats.timeout":"", "stats.confirmed-timeout":"",
            "stats.failure":"", "stats.type-unsupported":""
        }
        return tuple(base[c] for c in self.tree["columns"])

    def _row_from_result(self, r: Dict[str, Any]):
        stats = r.get("stats") or {}
        vendors = r.get("major_vendors") or {}
        base = {
            "indicator": r.get("indicator"),
            "detection_ratio": r.get("detection_ratio") or "",
            "vendor.Microsoft": vendors.get("Microsoft","n/a"),
            "vendor.Kaspersky": vendors.get("Kaspersky","n/a"),
            "vendor.Symantec": vendors.get("Symantec","n/a"),
            "vendor.TrendMicro": vendors.get("TrendMicro","n/a"),
            "vendor.BitDefender": vendors.get("BitDefender","n/a"),
            "vendor.ESET": vendors.get("ESET","n/a"),
            "error": r.get("error") or "",
            "stats.malicious": stats.get("malicious",0),
            "stats.suspicious": stats.get("suspicious",0),
            "stats.harmless": stats.get("harmless",0),
            "stats.undetected": stats.get("undetected",0),
            "stats.timeout": stats.get("timeout",0),
            "stats.confirmed-timeout": stats.get("confirmed-timeout",0),
            "stats.failure": stats.get("failure",0),
            "stats.type-unsupported": stats.get("type-unsupported",0),
        }
        return tuple(base[c] for c in self.tree["columns"])

    def apply_result(self, r: Dict[str, Any]):
        ioc = r.get("indicator")
        iid = self.row_index_by_indicator.get(ioc)
        if iid:
            vals = self._row_from_result(r)
            self.tree.item(iid, values=vals)
            err = (r.get("error") or "").strip()
            if err:
                self.tree.item(iid, tags=("error",))
            else:
                self.tree.item(iid, tags=())
        error_str=r.get('error')
        if error_str=="":
        	error_str="None"
        self.log_print(f"[{ioc}] {r.get('detection_ratio','')}  error={error_str}")
        # デバッグ出力
        print("=" * 80); from pprint import pprint as _pp; _pp(r); sys.stdout.flush()

    # ----- スキャン（バックグラウンド） -----
    def run_scan(self):
        if self.scanning:
            return
        raw = self.text.get("1.0", "end")
        iocs = parse_ioc_text(raw)
        if not iocs:
            messagebox.showinfo("実行", "IOC がありません。"); return

        # 表に未追加の行を先に用意
        for ioc in iocs:
            if ioc not in self.row_index_by_indicator:
                iid = self.tree.insert("", "end", values=self._blank_row(ioc))
                self.row_index_by_indicator[ioc] = iid

        # UIボタンを無効化
        self.scanning = True
        self.btn_run.config(state="disabled")
        self.btn_add.config(state="disabled")
        self.btn_clear.config(state="disabled")

        # 進捗キューのドレインを開始
        self.after(100, self._drain_progress_queue)

        def worker():
            try:
                for ioc in iocs:
                    retry_cnt=0
                    while True:
                        res = vt_query_one(ioc)                        
                        if res.get("error") == "rate limit exceeded":
                            retry_cnt+=1
                            if retry_cnt==3:
                                retry_cnt=0
                                self.progress_q.put({"__log__": f"[{ioc}] rate limit exceeded (retry failed)"})
                                break
                            # ログだけ即時更新したいので、専用メッセージをキューへ
                            self.progress_q.put({"__log__": f"[{ioc}] rate limit exceeded → {RETRY_SLEEP_SECONDS_ON_429}秒待機してリトライ"})
                            time.sleep(RETRY_SLEEP_SECONDS_ON_429)
                            continue
                        # 結果をキューへ
                        self.progress_q.put(res)
                        break
            finally:
                # 完了シグナル
                self.progress_q.put({"__done__": True})

        threading.Thread(target=worker, daemon=True).start()
        self.log_print(f"スキャン開始（{len(iocs)} 件 / キー {api_keys_count()}）…")

    def _drain_progress_queue(self):
        try:
            while True:
                item = self.progress_q.get_nowait()
                if "__done__" in item:
                    self.scanning = False
                    self.btn_run.config(state="normal")
                    self.btn_add.config(state="normal")
                    self.btn_clear.config(state="normal")
                    self.log_print("スキャン完了。")
                    self.update_usage_status()
                elif "__log__" in item:
                    self.log_print(item["__log__"])
                else:
                    self.apply_result(item)
        except queue.Empty:
            pass
        # 継続監視
        if self.scanning:
            self.after(120, self._drain_progress_queue)

    # ----- ログ -----
    def log_print(self, msg: str):
        self.log.config(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.config(state="normal")

    def log_delete_all(self):
        self.log.config(state="normal")
        self.log.delete("1.0", "end")
        self.log.config(state="normal")


if __name__ == "__main__":
    app = VTApp()
    app.mainloop()
