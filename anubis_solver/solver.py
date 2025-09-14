import concurrent.futures
import re
import requests
import time
from typing import Optional

from .utils import sha256, bytes_to_hex


def _fetch(url: str, cookie: Optional[str] = None) -> tuple[Optional[str], str]:
    headers = {"User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/58.0.3029.110 AnubisSolver/0.1.1 +https://pypi.org/project/anubis-solver/"),
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
               "Accept-Language": "en-US,en;q=0.5", }
    if cookie:
        headers["Cookie"] = cookie

    resp = requests.get(url, headers=headers, verify=False, allow_redirects=False)
    body = resp.text

    set_cookie = None
    if "Set-Cookie" in resp.headers:
        parts = []
        cookie_headers = []
        if hasattr(resp.raw, '_original_response') and hasattr(resp.raw._original_response, 'msg'):
            cookie_headers = resp.raw._original_response.msg.get_all('Set-Cookie') or []
        else:
            single_cookie = resp.headers.get("Set-Cookie")
            if single_cookie:
                cookie_headers = [single_cookie]
        for cookie_val in cookie_headers:
            cookie_part = cookie_val.split(";", 1)[0]
            if not cookie_part.endswith("="):
                parts.append(cookie_part)
        if parts:
            set_cookie = "; ".join(parts)
    return set_cookie, body


def _solve_pow(challenge: str, difficulty: int, threads: int = 8) -> int:
    from itertools import count
    stop = False
    result = None

    def worker(start: int):
        nonlocal stop, result
        for nonce in count(start, threads):
            if stop:
                return
            data = challenge + str(nonce)
            h = sha256(data)
            if all(b == 0 for b in h[:difficulty]):
                stop = True
                result = nonce
                return

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(worker, i) for i in range(threads)]
        concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)

    if result is None:
        raise RuntimeError("PoW solving failed")
    return result


def solve(endpoint: str, sleep: float = 1.0) -> str:
    requests.packages.urllib3.disable_warnings()

    cookie, body = _fetch(endpoint)

    final_cookie = None
    try:
        if "\"algorithm\":\"metarefresh\"" in body:
            m = re.search(r"url=/([^\"<]+)", body)
            if not m:
                raise RuntimeError("No URL in metarefresh challenge")
            url = endpoint.rstrip("/") + "/" + m.group(1).replace("&amp;", "&")
            time.sleep(sleep)
            c2, _ = _fetch(url, cookie)
            final_cookie = f"{cookie}; {c2}" if c2 else cookie
        elif "\"algorithm\":\"preact\"" in body:
            m_data = re.search(r"\"randomData\":\"([^\"]+)\"", body)
            m_id = re.search(r"\"id\":\"([^\"]+)\"", body)
            if not m_data or not m_id:
                raise RuntimeError("preact challenge parse error")
            solved = bytes_to_hex(sha256(m_data.group(1)))
            time.sleep(sleep)
            url = (endpoint.rstrip("/") + f"/.within.website/x/cmd/anubis/api/pass-challenge?"
                                          f"id={m_id.group(1)}&result={solved}&redir=%2F")
            c2, _ = _fetch(url, cookie)
            final_cookie = f"{cookie}; {c2}" if c2 else cookie
        else:  # assume PoW
            m_chal = re.search(r"\"challenge\":\"([^\"]+)\"", body)
            m_diff = re.search(r"\"difficulty\":(\d+)", body)
            if not (m_chal and m_diff):
                raise RuntimeError("PoW challenge parse error")

            chal = m_chal.group(1)
            diff = int(m_diff.group(1))

            ans = _solve_pow(chal, diff)
            h = sha256(chal + str(ans))
            hash_hex = bytes_to_hex(h)

            time.sleep(sleep)
            url = (endpoint.rstrip("/") + f"/.within.website/x/cmd/anubis/api/pass-challenge?"
                                          f"response={hash_hex}&nonce={ans}&elapsedTime=10&redir=%2F")
            c2, _ = _fetch(url, cookie)
            final_cookie = f"{cookie}; {c2}" if c2 else cookie
    except Exception as e:
        raise RuntimeError(f"Challenge solving failed: {e}")
    return final_cookie
