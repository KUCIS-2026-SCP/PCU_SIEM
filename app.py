import os
import subprocess
import re
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

# 파일 경로 정의
LOG_FILES = {
    "apache_access": "/var/log/apache2/access.log",
    "auth": "/var/log/auth.log",
    "apache_error": "/var/log/apache2/error.log"
}

def execute_cmd(cmd):
    """쉘 명령어를 안전하게 실행하고 결과를 반환"""
    try:
        result = subprocess.check_output(cmd, shell=True, text=True)
        return result.strip()
    except subprocess.CalledProcessError:
        return ""

def parse_keywords(input_str):
    """공백 또는 쉼표 기준으로 키워드를 리스트로 분리"""
    if not input_str:
        return []
    keywords = re.split(r'[\s,]+', input_str.strip())
    return [kw for kw in keywords if kw]

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/logs")
def get_logs():
    log_type = request.args.get("log_type", "apache_access")
    query_str = request.args.get("query", "")
    exclude_str = request.args.get("exclude", "")
    limit = request.args.get("limit", "100")

    log_path = LOG_FILES.get(log_type, LOG_FILES["apache_access"])

    # 키워드 파싱
    include_kws = parse_keywords(query_str)
    exclude_kws = parse_keywords(exclude_str)

    # 파이프라인 생성 (cat -> grep/awk -> tail)
    cmd = f"cat {log_path}"
    
    # 포함 키워드 처리
    if include_kws:
        if log_type == "apache_access" and all(kw.isdigit() and len(kw) == 3 for kw in include_kws):
            pattern = "^(" + "|".join(include_kws) + ")$"
            cmd += f" | awk '$9 ~ /{pattern}/'"
        else:
            pattern = "|".join([re.escape(kw) for kw in include_kws])
            cmd += f" | grep -i -E '{pattern}'"
        
    # 제외 키워드 처리
    for kw in exclude_kws:
        if kw:
            cmd += f" | grep -v -i '{re.escape(kw)}'"
        
    cmd += f" | tail -n {limit}"

    raw_output = execute_cmd(cmd)
    logs = raw_output.split("\n") if raw_output else []

    # 통계 계산
    total_cnt = execute_cmd(f"cat {log_path} | wc -l")

    if log_type == "apache_access":
        status_2xx = execute_cmd(f"cat {log_path} | awk '$9 ~ /^2[0-9]{{2}}$/' | wc -l")
        status_3xx = execute_cmd(f"cat {log_path} | awk '$9 ~ /^3[0-9]{{2}}$/' | wc -l")
        status_4xx = execute_cmd(f"cat {log_path} | awk '$9 ~ /^4[0-9]{{2}}$/' | wc -l")
        status_5xx = execute_cmd(f"cat {log_path} | awk '$9 ~ /^5[0-9]{{2}}$/' | wc -l")

        stats = {
            "type": "web",
            "total": int(total_cnt) if total_cnt.isdigit() else 0,
            "c1": int(status_2xx) if status_2xx.isdigit() else 0,
            "c2": int(status_3xx) if status_3xx.isdigit() else 0,
            "c3": int(status_4xx) if status_4xx.isdigit() else 0,
            "c4": int(status_5xx) if status_5xx.isdigit() else 0,
            "labels": ["2xx Success (정상)", "3xx Redirection (리다이렉션)", "4xx Client Error (클라이언트 오류)", "5xx Server Error (서버 오류)"],
            "filter_patterns": [
                "200 201 202 204 206",
                "301 302 304 307 308",
                "400 401 403 404 405 408 413 414 429",
                "500 501 502 503 504"
            ]
        }
    elif log_type == "auth":
        failed_cnt = execute_cmd(f"cat {log_path} | grep -i 'Failed password' | wc -l")
        accepted_cnt = execute_cmd(f"cat {log_path} | grep -i 'Accepted' | wc -l")
        sudo_cnt = execute_cmd(f"cat {log_path} | grep -i 'sudo' | wc -l")
        other_cnt = int(total_cnt if total_cnt.isdigit() else 0) - (int(failed_cnt or 0) + int(accepted_cnt or 0) + int(sudo_cnt or 0))

        stats = {
            "type": "auth",
            "total": int(total_cnt) if total_cnt.isdigit() else 0,
            "c1": int(accepted_cnt) if accepted_cnt.isdigit() else 0,
            "c2": int(failed_cnt) if failed_cnt.isdigit() else 0,
            "c3": int(sudo_cnt) if sudo_cnt.isdigit() else 0,
            "c4": max(0, other_cnt),
            "labels": ["Accepted (로그인 성공)", "Failed (로그인 실패/공격)", "sudo (권한 명령어 실행)", "기타 이벤트"],
            "filter_patterns": ["Accepted", "Failed", "sudo", ""]
        }
    else:  # apache_error
        err_cnt = execute_cmd(f"cat {log_path} | grep -i 'error' | wc -l")
        warn_cnt = execute_cmd(f"cat {log_path} | grep -i 'warn' | wc -l")
        notice_cnt = execute_cmd(f"cat {log_path} | grep -i 'notice' | wc -l")
        other_cnt = int(total_cnt if total_cnt.isdigit() else 0) - (int(err_cnt or 0) + int(warn_cnt or 0) + int(notice_cnt or 0))

        stats = {
            "type": "error",
            "total": int(total_cnt) if total_cnt.isdigit() else 0,
            "c1": int(notice_cnt) if notice_cnt.isdigit() else 0,
            "c2": int(warn_cnt) if warn_cnt.isdigit() else 0,
            "c3": int(err_cnt) if err_cnt.isdigit() else 0,
            "c4": max(0, other_cnt),
            "labels": ["Notice (일반 알림)", "Warn (경고)", "Error (에러 발생)", "기타"],
            "filter_patterns": ["notice", "warn", "error", ""]
        }

    return jsonify({
        "logs": logs,
        "stats": stats,
        "executed_cmd": cmd
    })

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>Integrated SIEM Console</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1a1a24; color: #fff; margin: 20px; }
        h1 { color: #00ff88; text-align: center; margin-bottom: 25px; }
        .container { display: flex; flex-wrap: wrap; gap: 20px; }
        .card { background: #242435; padding: 20px; border-radius: 10px; flex: 1; min-width: 320px; box-shadow: 0 4px 10px rgba(0,0,0,0.4); }
        .full-width { flex: 100%; }
        select, input, button { padding: 10px; border-radius: 5px; border: none; font-size: 14px; }
        select { background: #33334c; color: #00ff88; font-weight: bold; margin-right: 10px; }
        input[type="text"] { background: #33334c; color: #fff; width: 280px; margin-right: 10px; }
        button { background: #00ff88; color: #1a1a24; font-weight: bold; cursor: pointer; }
        button:hover { background: #00cc6a; }
        .cmd-box { background: #0d0d13; color: #00ff00; padding: 12px; font-family: monospace; border-radius: 5px; margin-top: 12px; border-left: 4px solid #00ff88; word-break: break-all; }
        .log-box { background: #0d0d13; color: #e0e0e0; padding: 15px; font-family: monospace; height: 380px; overflow-y: scroll; border-radius: 5px; white-space: pre-wrap; word-break: break-all; }
        .stat-val { font-size: 20px; font-weight: bold; color: #00e5ff; }
        .desc-box { background: #151520; padding: 15px; border-radius: 8px; margin-top: 15px; font-size: 13px; border-left: 4px solid #00e5ff; max-height: 240px; overflow-y: auto; }
        .desc-section { margin-bottom: 10px; }
        .desc-title { color: #00ff88; font-weight: bold; margin-bottom: 8px; }
        .desc-item { color: #ccc; margin-left: 8px; line-height: 1.4; }
    </style>
</head>
<body>

    <h1>🛡️ Raspberry Pi Integrated SIEM Console (Port 8080)</h1>

    <div class="container">
        <!-- 로그 선택 및 검색 -->
        <div class="card full-width">
            <h3>🔎 로그 데이터셋 선택 및 검색 필터</h3>
            <div>
                <select id="logType" onchange="resetAndFetch()">
                    <option value="apache_access">아파치 접속 로그 (/var/log/apache2/access.log)</option>
                    <option value="auth">시스템 인증 로그 (/var/log/auth.log)</option>
                    <option value="apache_error">아파치 에러 로그 (/var/log/apache2/error.log)</option>
                </select>
                <input type="text" id="query" placeholder="포함 단어들 (예: 400 403 404)">
                <input type="text" id="exclude" placeholder="제외 단어들 (공백 구분)">
                <button type="button" onclick="fetchData()">조회하기</button>
                <button type="button" onclick="resetAndFetch()" style="background:#555; color:#fff;">초기화</button>
            </div>

            <div class="cmd-box">실행된 Shell Command: <span id="executedCmd">-</span></div>
        </div>

        <!-- 수치 통계 카운터 및 설명 가이드 -->
        <div class="card">
            <h3>📊 로그 유형별 통계 (wc -l)</h3>
            <p>전체 로그 건수: <span id="totalLogs" class="stat-val">0</span> 건</p>
            <p><span id="l1">항목 1</span>: <span id="v1" class="stat-val" style="color:#69f0ae;">0</span> 건</p>
            <p><span id="l2">항목 2</span>: <span id="v2" class="stat-val" style="color:#64b5f6;">0</span> 건</p>
            <p><span id="l3">항목 3</span>: <span id="v3" class="stat-val" style="color:#ffd740;">0</span> 건</p>
            <p><span id="l4">항목 4</span>: <span id="v4" class="stat-val" style="color:#ff5252;">0</span> 건</p>

            <div class="desc-box" id="guideBox"></div>
        </div>

        <!-- 원형 차트 -->
        <div class="card">
            <h3>📈 대역/유형별 비율 (조각 클릭 시 필터링)</h3>
            <div style="width: 270px; margin: 0 auto;">
                <canvas id="pieChart"></canvas>
            </div>
        </div>

        <!-- 로그 출력 창 -->
        <div class="card full-width">
            <h3>📜 실시간 로그 출력 결과</h3>
            <div id="logConsole" class="log-box">로그 로딩 중...</div>
        </div>
    </div>

    <script>
        let myPieChart = null;
        let currentFilterPatterns = [];

        function updateGuideBox(logType) {
            const guide = document.getElementById('guideBox');
            if (logType === 'auth') {
                guide.innerHTML = `
                    <div class="desc-title">💡 System Auth Log 관제 가이드</div>
                    <div class="desc-section">
                        <div style="color:#69f0ae; font-weight:bold;">🟢 Accepted (로그인 성공)</div>
                        <div class="desc-item">• SSH 접속 성공 시각, 계정 및 접속 IP 확인 가능</div>
                    </div>
                    <div class="desc-section">
                        <div style="color:#ffd740; font-weight:bold;">🟡 Failed (로그인 실패)</div>
                        <div class="desc-item">• SSH 무차별 대입(Brute-force) 공격 시도 탐지</div>
                    </div>
                    <div class="desc-section">
                        <div style="color:#64b5f6; font-weight:bold;">🔵 sudo (권한 명령어 실행)</div>
                        <div class="desc-item">• 관리자 권한으로 실행된 명령어 실시간 추적</div>
                    </div>
                `;
            } else if (logType === 'apache_access') {
                guide.innerHTML = `
                    <div class="desc-title">💡 HTTP 상태 코드 대역 안내</div>
                    <div class="desc-section">
                        <div style="color:#69f0ae; font-weight:bold;">🟢 2xx (Success)</div>
                        <div class="desc-item">• 200 OK 등 정상 페이지 요청</div>
                    </div>
                    <div class="desc-section">
                        <div style="color:#64b5f6; font-weight:bold;">🔵 3xx (Redirection)</div>
                        <div class="desc-item">• 301 / 302 / 304 이동 및 캐시</div>
                    </div>
                    <div class="desc-section">
                        <div style="color:#ffd740; font-weight:bold;">🟡 4xx (Client Error)</div>
                        <div class="desc-item">• 400 / 401 / 403 / 404 스캔/차단</div>
                    </div>
                    <div class="desc-section">
                        <div style="color:#ff5252; font-weight:bold;">🔴 5xx (Server Error)</div>
                        <div class="desc-item">• 500 / 502 / 503 서버 스크립트 에러</div>
                    </div>
                `;
            } else {
                guide.innerHTML = `
                    <div class="desc-title">💡 Apache Error Log 안내</div>
                    <div class="desc-section">
                        <div class="desc-item">• Apache 웹 서버 모듈 및 SSL 에러 수집</div>
                    </div>
                `;
            }
        }

        function renderChart(stats) {
            const ctx = document.getElementById('pieChart').getContext('2d');
            currentFilterPatterns = stats.filter_patterns;

            if (myPieChart) {
                myPieChart.destroy();
            }

            myPieChart = new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: stats.labels,
                    datasets: [{
                        data: [stats.c1, stats.c2, stats.c3, stats.c4],
                        backgroundColor: ['#69f0ae', '#64b5f6', '#ffd740', '#ff5252']
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: { labels: { color: '#fff', font: { size: 11 } } }
                    },
                    onClick: (evt, activeElements) => {
                        if (activeElements.length > 0) {
                            const index = activeElements[0].index;
                            const clickedPattern = currentFilterPatterns[index];
                            if (clickedPattern) {
                                document.getElementById('query').value = clickedPattern;
                                fetchData();
                            }
                        }
                    }
                }
            });
        }

        function resetAndFetch() {
            document.getElementById('query').value = '';
            document.getElementById('exclude').value = '';
            fetchData();
        }

        function fetchData() {
            const logType = document.getElementById('logType').value;
            const query = document.getElementById('query').value;
            const exclude = document.getElementById('exclude').value;

            updateGuideBox(logType);

            fetch(`/api/logs?log_type=${logType}&query=${encodeURIComponent(query)}&exclude=${encodeURIComponent(exclude)}`)
                .then(res => res.json())
                .then(data => {
                    document.getElementById('logConsole').innerText = data.logs.join('\n') || '조건에 맞는 로그가 없습니다.';
                    document.getElementById('executedCmd').innerText = data.executed_cmd;

                    const s = data.stats;
                    document.getElementById('totalLogs').innerText = s.total;
                    document.getElementById('l1').innerText = s.labels[0]; document.getElementById('v1').innerText = s.c1;
                    document.getElementById('l2').innerText = s.labels[1]; document.getElementById('v2').innerText = s.c2;
                    document.getElementById('l3').innerText = s.labels[2]; document.getElementById('v3').innerText = s.c3;
                    document.getElementById('l4').innerText = s.labels[3]; document.getElementById('v4').innerText = s.c4;

                    renderChart(s);
                });
        }

        fetchData();
        setInterval(fetchData, 5000);
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
