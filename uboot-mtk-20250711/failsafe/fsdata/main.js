function normalizeLang(n) {
    if (!n) return "en";
    var t = String(n).toLowerCase();
    return t.indexOf("zh") === 0 ? "zh-cn" : "en"
}

function detectLang() {
    var t, n;
    try {
        if (t = localStorage.getItem("lang"), t) return normalizeLang(t)
    } catch (i) { }
    return n = [], navigator.languages && navigator.languages.length ? n = navigator.languages : navigator.language && (n = [navigator.language]), normalizeLang(n[0])
}

function detectTheme() {
    try {
        var n = localStorage.getItem("theme");
        if (n) return n
    } catch (t) { }
    return "auto"
}

function t(n) {
    var t = APP_STATE.lang || "en";
    return I18N[t] && I18N[t][n] !== undefined ? I18N[t][n] : I18N.en && I18N.en[n] !== undefined ? I18N.en[n] : n
}

function applyI18n(n) {
    for (var c, u, i, l, f, r, a, e, v, y, s = n || document, h = s.querySelectorAll("[data-i18n]"), o = 0; o < h.length; o++) c = h[o].getAttribute("data-i18n"), h[o].textContent = t(c);
    for (u = s.querySelectorAll("[data-i18n-html]"), i = 0; i < u.length; i++) l = u[i].getAttribute("data-i18n-html"), u[i].innerHTML = t(l);
    for (f = s.querySelectorAll("[data-i18n-attr]"), r = 0; r < f.length; r++) a = f[r].getAttribute("data-i18n-attr"), e = a.split(":"), e.length >= 2 && (v = e[0], y = e.slice(1).join(":"), f[r].setAttribute(v, t(y)))
}

function setLang(n) {
    APP_STATE.lang = normalizeLang(n);
    try {
        localStorage.setItem("lang", APP_STATE.lang)
    } catch (t) { }
    applyI18n(document);
    typeof backupRefreshI18n == "function" && APP_STATE.page === "backup" && backupRefreshI18n();
    typeof renderSysInfo == "function" && renderSysInfo();
    updateDocumentTitle()
}

function setTheme(n) {
    APP_STATE.theme = n || "auto";
    try {
        localStorage.setItem("theme", APP_STATE.theme)
    } catch (i) { }
    var t = document.documentElement;
    APP_STATE.theme === "auto" ? t.removeAttribute("data-theme") : t.setAttribute("data-theme", APP_STATE.theme)
}

function updateDocumentTitle() {
    if (APP_STATE.page) {
        var n = APP_STATE.page + ".title";
        if (I18N[APP_STATE.lang] && I18N[APP_STATE.lang][n]) {
            document.title = t(n);
            return
        }
        APP_STATE.page === "flashing" ? document.title = t("flashing.title.in_progress") : APP_STATE.page === "booting" && (document.title = t("booting.title.in_progress"))
    }
}

function ensureBranding() {
    var t = document.getElementById("version"),
        n, i;
    t && ((n = t.nextElementSibling, n && n.classList && n.classList.contains("brand") && n.parentNode && n.parentNode.removeChild(n), t.querySelector && t.querySelector(".brand-inline")) || (i = document.createElement("span"), i.className = "brand-inline", i.textContent = "💡Yuzhii", t.appendChild(document.createTextNode(" ")), t.appendChild(i)))
    if (!t) return;
    if (t.querySelector && t.querySelector("#project-info")) return;
    var m = document.createElement("div");
    m.id = "project-info";
    m.innerHTML = 'You can find more infomation about this project: <a href="https://github.com/Yuzhii0718/bl-mt798x-dhcpd" target="_blank">Github</a>';
    t.appendChild(m);
}

function ensureSidebar() {
    function o(n, i, r) {
        var u = document.createElement("a"),
            s, o, e, h;
        return u.className = "nav-link", u.href = n, u.setAttribute("data-nav-id", r), s = document.createElement("span"), s.className = "dot", u.appendChild(s), o = document.createElement("span"), o.setAttribute("data-i18n", i), o.textContent = t(i), u.appendChild(o), e = n, e !== "/" && e.charAt(0) !== "/" && (e = "/" + e), h = e === f || e === "/" && (f === "/" || f === "/index.html"), h && u.classList.add("active"), u
    }
    var i = document.getElementById("sidebar"),
        f, k, s, h, c, d, r, l, g, n, a, v, y, p, e, w, u, b;
    i && i.getAttribute("data-rendered") !== "1" && (i.setAttribute("data-rendered", "1"), f = location && location.pathname ? location.pathname : "", f === "" && (f = "/"), i.innerHTML = "", k = document.createElement("div"), k.className = "sidebar-brand", s = document.createElement("div"), s.className = "title", s.setAttribute("data-i18n", "app.name"), s.textContent = t("app.name"), k.appendChild(s), i.appendChild(k), h = document.createElement("div"), h.className = "sidebar-controls", c = document.createElement("div"), c.className = "control-row", d = document.createElement("div"), d.setAttribute("data-i18n", "control.language"), d.textContent = t("control.language"), c.appendChild(d), r = document.createElement("select"), r.id = "lang_select", r.innerHTML = '<option value="en">English<\/option><option value="zh-cn">简体中文<\/option>', r.value = APP_STATE.lang, r.onchange = function () {
        setLang(this.value)
    }, c.appendChild(r), h.appendChild(c), l = document.createElement("div"), l.className = "control-row", g = document.createElement("div"), g.setAttribute("data-i18n", "control.theme"), g.textContent = t("control.theme"), l.appendChild(g), n = document.createElement("select"), n.id = "theme_select", a = document.createElement("option"), a.value = "auto", a.setAttribute("data-i18n", "theme.auto"), a.textContent = t("theme.auto"), v = document.createElement("option"), v.value = "light", v.setAttribute("data-i18n", "theme.light"), v.textContent = t("theme.light"), y = document.createElement("option"), y.value = "dark", y.setAttribute("data-i18n", "theme.dark"), y.textContent = t("theme.dark"), n.appendChild(a), n.appendChild(v), n.appendChild(y), n.value = APP_STATE.theme, n.onchange = function () {
        setTheme(this.value)
    }, l.appendChild(n), h.appendChild(l), i.appendChild(h), p = document.createElement("div"), p.className = "nav", e = document.createElement("div"), e.className = "nav-section", w = document.createElement("div"), w.className = "nav-section-title", w.setAttribute("data-i18n", "nav.basic"), w.textContent = t("nav.basic"), e.appendChild(w), e.appendChild(o("/", "nav.firmware", "firmware")), e.appendChild(o("/uboot.html", "nav.uboot", "uboot")), p.appendChild(e), u = document.createElement("div"), u.className = "nav-section", b = document.createElement("div"), b.className = "nav-section-title", b.setAttribute("data-i18n", "nav.advanced"), b.textContent = t("nav.advanced"), u.appendChild(b), u.appendChild(o("/bl2.html", "nav.bl2", "bl2")), u.appendChild(o("/gpt.html", "nav.gpt", "gpt")), u.appendChild(o("/factory.html", "nav.factory", "factory")), u.appendChild(o("/initramfs.html", "nav.initramfs", "initramfs")), p.appendChild(u), u = document.createElement("div"), u.className = "nav-section", b = document.createElement("div"), b.className = "nav-section-title", b.setAttribute("data-i18n", "nav.system"), b.textContent = t("nav.system"), u.appendChild(b), u.appendChild(o("/backup.html", "nav.backup", "backup")), u.appendChild(o("/env.html", "nav.env", "env")), u.appendChild(o("/console.html", "nav.console", "console")), r = o("/reboot.html", "nav.reboot", "reboot"), r.onclick = function () {
        return confirm(t("reboot.confirm"))
    }, u.appendChild(r), p.appendChild(u), i.appendChild(p), applyI18n(i))
}

function ajax(n) {
    var t, i;
    t = window.XMLHttpRequest ? new XMLHttpRequest : new ActiveXObject("Microsoft.XMLHTTP");
    t.upload.addEventListener("progress", function (t) {
        n.progress && n.progress(t)
    });
    t.onreadystatechange = function () {
        t.readyState == 4 && t.status == 200 && n.done && n.done(t.responseText)
    };
    n.timeout && (t.timeout = n.timeout);
    i = "GET";
    n.data && (i = "POST");
    t.open(i, n.url);
    t.send(n.data)
}

function consoleInit() {
    var out = document.getElementById("console_out");
    var cmd = document.getElementById("console_cmd");
    var status = document.getElementById("console_status");
    var token = document.getElementById("console_token");
    var persistKey = "failsafe_console_output";
    var persistMax = 200000;

    APP_STATE.console = APP_STATE.console || {
        running: false,
        pollTimer: null,
        history: [],
        histPos: -1,
        tokenKey: "failsafe_console_token"
    };

    function loadToken() {
        try {
            var t = localStorage.getItem(APP_STATE.console.tokenKey);
            token && t && (token.value = t);
        } catch (e) { }
    }

    function saveToken() {
        try {
            token && localStorage.setItem(APP_STATE.console.tokenKey, token.value || "");
        } catch (e) { }
    }

    function setStatus(t) {
        status && (status.textContent = t || "");
    }

    function loadPersistedOutput() {
        if (!out) return;
        try {
            var s = sessionStorage.getItem(persistKey);
            if (s) out.textContent = s;
        } catch (e) { }
    }

    function savePersistedOutput() {
        if (!out) return;
        try {
            var s = out.textContent || "";
            if (s.length > persistMax)
                s = s.slice(s.length - persistMax);
            sessionStorage.setItem(persistKey, s);
        } catch (e) { }
    }

    function appendText(t) {
        if (!out) return;
        if (!t) return;
        out.textContent += t;
        if (out.textContent.length > persistMax)
            out.textContent = out.textContent.slice(out.textContent.length - persistMax);
        savePersistedOutput();
        out.scrollTop = out.scrollHeight;
    }

    async function pollOnce() {
        if (!APP_STATE.console.running) return;
        try {
            var fd = new FormData();
            if (token && token.value) fd.append("token", token.value);
            var r = await fetch("/console/poll", { method: "POST", body: fd });
            if (!r.ok) {
                setStatus(t("console.status.http") + " " + r.status);
                return;
            }
            var txt = await r.text();
            var j;
            try {
                j = JSON.parse(txt);
            } catch (e) {
                setStatus(t("console.status.parse"));
                return;
            }
            j && j.data && appendText(j.data);
        } catch (e) {
            setStatus(t("console.status.error") + " " + (e && e.message ? e.message : String(e)));
        }
    }

    function schedulePoll() {
        APP_STATE.console.pollTimer && clearTimeout(APP_STATE.console.pollTimer);
        APP_STATE.console.pollTimer = setTimeout(async function () {
            await pollOnce();
            schedulePoll();
        }, 300);
    }

    window.consoleSend = async function () {
        if (!cmd || !cmd.value) return;
        saveToken();
        var line = String(cmd.value);
        cmd.value = "";
        APP_STATE.console.history.unshift(line);
        APP_STATE.console.history.length > 50 && (APP_STATE.console.history.length = 50);
        APP_STATE.console.histPos = -1;

        try {
            var fd = new FormData();
            fd.append("cmd", line);
            if (token && token.value) fd.append("token", token.value);
            setStatus(t("console.status.running"));
            var r = await fetch("/console/exec", { method: "POST", body: fd });
            var txt = await r.text();
            if (!r.ok) {
                setStatus(t("console.status.http") + " " + r.status + (txt ? ": " + txt : ""));
                return;
            }
            try {
                var j = JSON.parse(txt);
                setStatus(t("console.status.ret") + " " + (j && typeof j.ret !== "undefined" ? j.ret : "?"));
            } catch (e) {
                setStatus(t("console.status.done"));
            }
        } catch (e) {
            setStatus(t("console.status.error") + " " + (e && e.message ? e.message : String(e)));
        }
    };

    window.consoleClear = async function () {
        saveToken();
        try {
            var fd = new FormData();
            if (token && token.value) fd.append("token", token.value);
            var r = await fetch("/console/clear", { method: "POST", body: fd });
            if (r.ok) {
                out && (out.textContent = "");
                try { sessionStorage.removeItem(persistKey); } catch (e) { }
                setStatus(t("console.status.cleared"));
            } else {
                setStatus(t("console.status.http") + " " + r.status);
            }
        } catch (e) {
            setStatus(t("console.status.error") + " " + (e && e.message ? e.message : String(e)));
        }
    };

    if (cmd) {
        cmd.addEventListener("keydown", function (e) {
            if (e.key === "Enter") {
                e.preventDefault();
                window.consoleSend();
                return;
            }
            if (e.key === "ArrowUp") {
                var h = APP_STATE.console.history;
                if (!h || !h.length) return;
                APP_STATE.console.histPos = Math.min(h.length - 1, APP_STATE.console.histPos + 1);
                cmd.value = h[APP_STATE.console.histPos] || "";
                e.preventDefault();
                return;
            }
            if (e.key === "ArrowDown") {
                var h2 = APP_STATE.console.history;
                if (!h2 || !h2.length) return;
                APP_STATE.console.histPos = Math.max(-1, APP_STATE.console.histPos - 1);
                cmd.value = APP_STATE.console.histPos >= 0 ? (h2[APP_STATE.console.histPos] || "") : "";
                e.preventDefault();
            }
        });
    }

    APP_STATE.console.running = true;
    loadToken();
    loadPersistedOutput();
    setStatus(t("console.status.ready"));
    schedulePoll();
}

function envInit() {
    var list = document.getElementById("env_list");
    var name = document.getElementById("env_name");
    var value = document.getElementById("env_value");
    var status = document.getElementById("env_status");
    var count = document.getElementById("env_count");
    var file = document.getElementById("env_file");

    function setStatus(t) {
        status && (status.textContent = t || "");
    }

    function countLines(txt) {
        if (!txt) return 0;
        var lines = txt.split("\n");
        var c = 0;
        for (var i = 0; i < lines.length; i++) {
            if (lines[i] && lines[i].indexOf("=") > 0)
                c++;
        }
        return c;
    }

    window.envRefresh = async function () {
        try {
            setStatus(t("env.status.loading"));
            var r = await fetch("/env/list", { method: "GET" });
            if (!r.ok) {
                setStatus(t("env.status.http") + " " + r.status);
                return;
            }
            var txt = await r.text();
            list && (list.textContent = txt || "");
            count && (count.textContent = t("env.count") + " " + countLines(txt));
            setStatus(t("env.status.ready"));
        } catch (e) {
            setStatus(t("env.status.error") + " " + (e && e.message ? e.message : String(e)));
        }
    };

    window.envSet = async function () {
        if (!name || !name.value) {
            alert(t("env.error.no_name"));
            return;
        }
        try {
            var fd = new FormData();
            fd.append("name", name.value);
            fd.append("value", value ? value.value : "");
            setStatus(t("env.status.saving"));
            var r = await fetch("/env/set", { method: "POST", body: fd });
            var txt = await r.text();
            if (!r.ok) {
                setStatus(t("env.status.error") + " " + (txt || r.status));
                return;
            }
            setStatus(t("env.status.saved"));
            window.envRefresh();
        } catch (e) {
            setStatus(t("env.status.error") + " " + (e && e.message ? e.message : String(e)));
        }
    };

    window.envUnset = async function () {
        if (!name || !name.value) {
            alert(t("env.error.no_name"));
            return;
        }
        if (!confirm(t("env.confirm.delete") + " " + name.value + " ?"))
            return;
        try {
            var fd = new FormData();
            fd.append("name", name.value);
            setStatus(t("env.status.saving"));
            var r = await fetch("/env/unset", { method: "POST", body: fd });
            var txt = await r.text();
            if (!r.ok) {
                setStatus(t("env.status.error") + " " + (txt || r.status));
                return;
            }
            setStatus(t("env.status.deleted"));
            window.envRefresh();
        } catch (e) {
            setStatus(t("env.status.error") + " " + (e && e.message ? e.message : String(e)));
        }
    };

    window.envReset = async function () {
        if (!confirm(t("env.confirm.reset")))
            return;
        try {
            setStatus(t("env.status.saving"));
            var r = await fetch("/env/reset", { method: "POST" });
            var txt = await r.text();
            if (!r.ok) {
                setStatus(t("env.status.error") + " " + (txt || r.status));
                return;
            }
            setStatus(t("env.status.reset"));
            window.envRefresh();
        } catch (e) {
            setStatus(t("env.status.error") + " " + (e && e.message ? e.message : String(e)));
        }
    };

    window.envRestore = async function () {
        if (!file || !file.files || !file.files.length) {
            alert(t("env.error.no_file"));
            return;
        }
        if (!confirm(t("env.confirm.restore")))
            return;
        try {
            var fd = new FormData();
            fd.append("envfile", file.files[0]);
            setStatus(t("env.status.saving"));
            var r = await fetch("/env/restore", { method: "POST", body: fd });
            var txt = await r.text();
            if (!r.ok) {
                setStatus(t("env.status.error") + " " + (txt || r.status));
                return;
            }
            setStatus(t("env.status.restored"));
            window.envRefresh();
        } catch (e) {
            setStatus(t("env.status.error") + " " + (e && e.message ? e.message : String(e)));
        }
    };

    window.envRefresh();
}

function appInit(n) {
    APP_STATE.page = n || "";
    APP_STATE.lang = detectLang();
    APP_STATE.theme = detectTheme();
    setTheme(APP_STATE.theme);
    setLang(APP_STATE.lang);
    ensureSidebar();
    ensureBranding();
    applyI18n(document);
    updateDocumentTitle();
    setTimeout(function () {
        document.body.classList.add("ready")
    }, 0);
    getversion();
    // Fetch system info and storage/partition info for display
    getSysInfo();
    getStorageInfoForSysinfo();
    // getCurrentMtdLayout();
    (n === "index" || n === "initramfs") && getmtdlayoutlist();
    n === "backup" && backupInit();
    n === "console" && consoleInit();
    n === "env" && envInit()
}

function updateGptNavVisibility() {
    // Hide GPT update entry when no MMC is present (runtime detection).
    // If backupinfo is unavailable, keep it visible (fallback behavior).
    var el = document.querySelector("#sidebar [data-nav-id='gpt']");
    if (!el) return;
    var bi = APP_STATE.backupinfo;
    if (bi && bi.mmc && bi.mmc.present === false) {
        el.style.display = "none";
    } else {
        el.style.display = "";
    }
}

function renderSysInfo() {
    var n = document.getElementById("sysinfo"), i, r, u, f, e;
    if (!n) return;
    i = APP_STATE.sysinfo;
    if (!i) {
        n.textContent = t("sysinfo.loading");
        return
    }
    u = i.board || {};
    f = i.ram || {};
    e = [];
    e.push(t("sysinfo.board") + " " + (u.model || t("sysinfo.unknown")));
    f.size !== undefined && f.size !== null && f.size !== 0 ? e.push(t("sysinfo.ram") + " " + bytesToHuman(f.size)) : e.push(t("sysinfo.ram") + " " + t("sysinfo.unknown"));

    n.textContent = e.join("\n")
}

function getSysInfo() {
    // Always fetch sysinfo into APP_STATE (used by features like backup filename),
    // but only render when the sysinfo element exists on current page.
    var n = document.getElementById("sysinfo");
    n && renderSysInfo();
    ajax({
        url: "/sysinfo",
        done: function (txt) {
            try {
                APP_STATE.sysinfo = JSON.parse(txt)
            } catch (t) {
                return
            }
            n && renderSysInfo()
        }
    })
}

async function ensureSysInfoLoaded() {
    // On pages without #sysinfo (e.g. backup.html), we still need board model.
    if (APP_STATE.sysinfo && APP_STATE.sysinfo.board && APP_STATE.sysinfo.board.model)
        return APP_STATE.sysinfo;

    if (APP_STATE._sysinfo_promise)
        return await APP_STATE._sysinfo_promise;

    APP_STATE._sysinfo_promise = (async function () {
        try {
            var r = await fetch("/sysinfo", { method: "GET" });
            if (!r || !r.ok) return null;
            var j = await r.json();
            j && (APP_STATE.sysinfo = j);
            return j;
        } catch (e) {
            return null;
        } finally {
            // allow retry later
            APP_STATE._sysinfo_promise = null;
        }
    })();

    return await APP_STATE._sysinfo_promise;
}

function getStorageInfoForSysinfo() {
    // Pull /backup/info to render current partition table in the sysinfo box
    if (APP_STATE.backupinfo) {
        updateGptNavVisibility();
        return;
    }
    ajax({
        url: "/backup/info",
        done: function (txt) {
            try {
                APP_STATE.backupinfo = JSON.parse(txt);
            } catch (e) { return; }
            updateGptNavVisibility();
            renderSysInfo();
        }
    });
}

function getCurrentMtdLayout() {
    // Get current mtd layout label if multi-layout is enabled
    ajax({
        url: "/getmtdlayout",
        done: function (resp) {
            if (!resp || resp === "error") return;
            var parts = resp.split(";");
            if (parts.length > 0 && parts[0]) {
                APP_STATE.mtd_layout_current = parts[0];
                renderSysInfo();
            }
        }
    });
}

function startup() {
    appInit("index")
}

function getmtdlayoutlist() {
    ajax({
        url: "/getmtdlayout",
        done: function (n) {
            var i, f, e, u, r, o;
            if (n != "error" && (i = n.split(";"), f = document.getElementById("current_mtd_layout"), f && (f.innerHTML = t("label.current_mtd") + i[0]), e = document.getElementById("choose_mtd_layout"), e && (e.textContent = t("label.choose_mtd")), u = document.getElementById("mtd_layout_label"), u)) {
                for (u.options.length = 0, r = 1; r < i.length; r++) i[r].length > 0 && u.options.add(new Option(i[r], i[r]));
                o = document.getElementById("mtd_layout");
                o && (o.style.display = "")
            }
        }
    })
}

function getversion() {
    ajax({
        url: "/version",
        done: function (n) {
            var t = document.getElementById("version");
            t && (t.innerHTML = n);
            ensureBranding()
        }
    })
}

function upload(n) {
    var o = document.getElementById("file").files[0],
        u, f, e, r, i, s;
    o && (u = document.getElementById("form"), u && (u.style.display = "none"), f = document.getElementById("hint"), f && (f.style.display = "none"), e = document.getElementById("bar"), e && (e.style.display = "block"), r = new FormData, r.append(n, o), i = document.getElementById("mtd_layout_label"), i && i.options.length > 0 && (s = i.selectedIndex, r.append("mtd_layout", i.options[s].value)), ajax({
        url: "/upload",
        data: r,
        done: function (n) {
            var i, r, u, f, e;
            n == "fail" ? location = "/fail.html" : (i = n.split(" "), r = document.getElementById("size"), r && (r.style.display = "block", r.innerHTML = t("label.size") + i[0]), u = document.getElementById("md5"), u && (u.style.display = "block", u.innerHTML = t("label.md5") + i[1]), f = document.getElementById("mtd"), f && i[2] && (f.style.display = "block", f.innerHTML = t("label.mtd") + i[2]), e = document.getElementById("upgrade"), e && (e.style.display = "block"))
        },
        progress: function (n) {
            if (n.total) {
                var i = parseInt(n.loaded / n.total * 100),
                    t = document.getElementById("bar");
                t && (t.style.display = "block", t.style.setProperty("--percent", i))
            }
        }
    }))
}

function bytesToHuman(n) {
    var t;
    return n === null || n === undefined ? "" : (t = Number(n), !isFinite(t) || t < 0) ? "" : t >= 1024 * 1024 * 1024 ? (t / (1024 * 1024 * 1024)).toFixed(2) + " GiB" : t >= 1024 * 1024 ? (t / (1024 * 1024)).toFixed(2) + " MiB" : t >= 1024 ? (t / 1024).toFixed(2) + " KiB" : String(Math.floor(t)) + " B"
}

function parseFilenameFromDisposition(n) {
    var t, i;
    return n ? (t = /filename\s*=\s*"([^"]+)"/i.exec(n), t && t[1]) ? t[1] : (i = /filename\s*=\s*([^;\s]+)/i.exec(n), i && i[1] ? i[1].replace(/^"|"$/g, "") : "") : ""
}

function sanitizeFilenameComponent(n) {
    return n ? String(n).replace(/[^a-zA-Z0-9._-]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 48) : ""
}

function getNowYYYYMMDD() {
    var n = new Date, t = n.getFullYear(), i = n.getMonth() + 1, r = n.getDate();
    return String(t) + String(i).padStart(2, "0") + String(r).padStart(2, "0")
}

function makeBackupDownloadName(n) {
    var u = (APP_STATE.sysinfo && APP_STATE.sysinfo.board && APP_STATE.sysinfo.board.model) ? APP_STATE.sysinfo.board.model : "";
    var t = sanitizeFilenameComponent(u) || "board";
    var i = getNowYYYYMMDD();
    var r = String(n || "backup.bin");

    // Ensure it starts with backup_
    r.indexOf("backup_") === 0 || (r = "backup_" + r.replace(/^_+/, ""));

    // Insert board right after backup_ if not already
    r.indexOf("backup_" + t + "_") === 0 || (r = r.replace(/^backup_/, "backup_" + t + "_"));

    // Ensure .bin extension
    /\.[A-Za-z0-9]+$/.test(r) || (r = r + ".bin");

    // Append date before extension if not already present
    /_\d{8}\.[A-Za-z0-9]+$/.test(r) || (r = r.replace(/(\.[A-Za-z0-9]+)$/, "_" + i + "$1"));

    return r
}

function parseUserLen(n) {
    var t, i, r;
    if (!n) return null;
    if (n = String(n).trim(), n === "") return null;
    t = /^\s*(0x[0-9a-fA-F]+|\d+)\s*([a-zA-Z]*)\s*$/.exec(n);
    if (!t) return null;
    i = t[1].toLowerCase().indexOf("0x") === 0 ? parseInt(t[1], 16) : parseInt(t[1], 10);
    if (!isFinite(i) || i < 0) return null;
    r = (t[2] || "").toLowerCase();
    return r === "" ? i : r === "k" || r === "kb" || r === "kib" ? i * 1024 : null
}

function setBackupStatus(n) {
    var t = document.getElementById("backup_status");
    t && (t.style.display = n ? "block" : "none", t.textContent = n || "")
}

function setBackupProgress(n) {
    var t = document.getElementById("bar"), i;
    t && (i = Math.max(0, Math.min(100, parseInt(n || 0))), t.style.display = "block", t.style.setProperty("--percent", i))
}

function backupUpdateRangeHint() {
    var u = document.getElementById("backup_range_hint"), n, i, r;
    u && (n = parseUserLen(document.getElementById("backup_start").value), i = parseUserLen(document.getElementById("backup_end").value), n === null || i === null ? u.textContent = t("backup.range.hint") : (r = i >= n ? i - n : 0, u.textContent = "Start=" + bytesToHuman(n) + ", End=" + bytesToHuman(i) + ", Size=" + bytesToHuman(r)))
}

function backupRefreshI18n() {
    var n = document.getElementById("backup_target"), t, r, u;
    if (!n) return;
    for (t = 0; t < n.options.length; t++) r = n.options[t], r && r.dataset && r.dataset.i18nKey && (r.textContent = window.t(r.dataset.i18nKey));
    for (t = 0; t < n.options.length; t++) {
        r = n.options[t];
        if (!r || !r.dataset) continue;
        r.dataset.kind === "mtd-full" && (u = r.dataset.mtdName || "", r.textContent = "[MTD] " + window.t("backup.target.full_disk") + (u ? " (" + u + ")" : "") + (r.dataset.size ? " (" + bytesToHuman(parseInt(r.dataset.size, 10)) + ")" : ""))
    }
}

function backupInit() {
    var u = document.getElementById("backup_mode"), r = document.getElementById("backup_range"), n = document.getElementById("backup_target"), s = document.getElementById("backup_target_field"), c = document.getElementById("backup_mode_target_row"), updateBackupUi, f, e;
    function o(t) {
        for (var i = 0; i < n.options.length; i++) if (n.options[i].value === t) return n.selectedIndex = i, true;
        return false
    }
    function h(t) {
        for (var i = 0; i < n.options.length; i++) if (n.options[i].dataset && n.options[i].dataset.kind === t) return n.selectedIndex = i, true;
        return false
    }
    function l() {
        for (var t = 0; t < n.options.length; t++) if (n.options[t].value) {
            n.selectedIndex = t;
            return true
        }
        return false
    }
    function a() {
        var t, i;
        if (!n || n.options.length <= 1) return;
        t = n.options[n.selectedIndex];
        i = t && t.dataset ? t.dataset.kind : "";
        (i === "mmc-part" || i === "mtd-part" || !n.value) && (o("mmc:raw") || h("mtd-full") || l())
    }
    u && r && n && (updateBackupUi = function () {
        var t = u.value === "range";
        t ? (r.style.display = "block", a(), backupUpdateRangeHint()) : (r.style.display = "none");
        s && (s.style.display = t ? "none" : "");
        c && (c.style.gridTemplateColumns = t ? "1fr" : "")
    }, u.onchange = updateBackupUi, f = document.getElementById("backup_start"), e = document.getElementById("backup_end"), f && (f.oninput = backupUpdateRangeHint), e && (e.oninput = backupUpdateRangeHint), updateBackupUi(), setBackupStatus(""), ajax({
        url: "/backup/info",
        done: function (u) {
            var r, e, o, s, f;
            try {
                r = JSON.parse(u)
            } catch (h) {
                setBackupStatus("backupinfo parse failed");
                return
            }
            e = document.getElementById("backup_info");
            e && (o = [], r.mmc && r.mmc.present ? o.push("MMC: " + (r.mmc.vendor || "") + " " + (r.mmc.product || "")) : o.push("MMC: " + t("backup.storage.not_present")), r.mtd && r.mtd.present ? o.push("MTD: " + (r.mtd.model || "")) : o.push("MTD: " + t("backup.storage.not_present")), e.textContent = o.join(" | "));
            n.options.length = 0;
            s = document.createElement("option");
            s.value = "";
            s.dataset.i18nKey = "backup.target.placeholder";
            n.appendChild(s);
            r.mmc && r.mmc.present && (f = document.createElement("option"), f.value = "mmc:raw", f.textContent = "[MMC] raw", f.dataset.kind = "mmc-raw", n.appendChild(f), r.mmc.parts && r.mmc.parts.length && r.mmc.parts.forEach(function (t) {
                var i;
                t && t.name && (i = document.createElement("option"), i.value = "mmc:" + t.name, i.textContent = "[MMC] " + t.name + (t.size ? " (" + bytesToHuman(t.size) + ")" : ""), i.dataset.kind = "mmc-part", n.appendChild(i))
            }));

            if (r.mtd && r.mtd.present && r.mtd.parts && r.mtd.parts.length) {
                var c = r.mtd.type, l = c === 3 || c === 4 || c === 8, a = [];
                l && r.mtd.parts.forEach(function (n) {
                    n && n.name && n.master && a.push(n)
                });

                l && a.length && a.forEach(function (p) {
                    var i = document.createElement("option");
                    i.value = "mtd:" + p.name;
                    i.dataset.mtdName = p.name;
                    i.dataset.size = p.size ? String(p.size) : "";
                    i.dataset.kind = "mtd-full";
                    n.appendChild(i)
                });

                r.mtd.parts.forEach(function (t) {
                    var i;
                    if (!t || !t.name) return;
                    if (l && t.master) return;
                    i = document.createElement("option");
                    i.value = "mtd:" + t.name;
                    i.textContent = "[MTD] " + t.name + (t.size ? " (" + bytesToHuman(t.size) + ")" : "");
                    i.dataset.kind = "mtd-part";
                    n.appendChild(i)
                })
            }
            n.options.length > 1 && (n.selectedIndex = 1);
            backupRefreshI18n();
            updateBackupUi && updateBackupUi()
        }
    }))
}

async function startBackup() {
    var u = document.getElementById("backup_mode"), f = document.getElementById("backup_target"), i, r, e, o, s, h, c, l, a, v, y, p, w, b, k;
    if (!u || !f) return;
    if (i = u.value, r = f.value, !r) {
        alert(t("backup.error.no_target"));
        return
    }
    e = new FormData;
    e.append("mode", i);
    e.append("storage", "auto");
    e.append("target", r);
    if (i === "range") {
        o = document.getElementById("backup_start");
        s = document.getElementById("backup_end");
        if (!o || !s || !o.value || !s.value) {
            alert(t("backup.error.bad_range"));
            return
        }
        e.append("start", o.value);
        e.append("end", s.value)
    }
    setBackupProgress(0);
    setBackupStatus(t("backup.status.starting"));
    try {
        h = await fetch("/backup/main", { method: "POST", body: e });
        if (!h.ok) {
            setBackupStatus(t("backup.error.http") + " " + h.status);
            return
        }
        c = h.headers.get("Content-Length");
        l = c ? parseInt(c, 10) : 0;
        a = parseFilenameFromDisposition(h.headers.get("Content-Disposition"));
        a || (a = "backup.bin");
        // Ensure we have board info for filename even on pages without #sysinfo
        await ensureSysInfoLoaded();
        a = makeBackupDownloadName(a);
        v = 0;
        if (window.showSaveFilePicker) {
            y = await window.showSaveFilePicker({ suggestedName: a, types: [{ description: "Binary", accept: { "application/octet-stream": [".bin"] } }] });
            p = await y.createWritable();
            w = h.body.getReader();
            while (true) {
                b = await w.read();
                if (b.done) break;
                await p.write(b.value);
                v += b.value.length;
                l ? setBackupProgress(v / l * 100) : setBackupProgress(0);
                setBackupStatus(t("backup.status.downloading") + " " + bytesToHuman(v) + (l ? " / " + bytesToHuman(l) : ""))
            }
            await p.close();
            setBackupProgress(100);
            setBackupStatus(t("backup.status.done") + " " + a)
        } else {
            k = [];
            w = h.body.getReader();
            while (true) {
                b = await w.read();
                if (b.done) break;
                k.push(b.value);
                v += b.value.length;
                l ? setBackupProgress(v / l * 100) : setBackupProgress(0);
                setBackupStatus(t("backup.status.downloading") + " " + bytesToHuman(v) + (l ? " / " + bytesToHuman(l) : ""))
            }
            setBackupProgress(100);
            setBackupStatus(t("backup.status.preparing"));
            p = new Blob(k, { type: "application/octet-stream" });
            y = document.createElement("a");
            y.href = URL.createObjectURL(p);
            y.download = a;
            document.body.appendChild(y);
            y.click();
            document.body.removeChild(y);
            setBackupStatus(t("backup.status.done") + " " + a)
        }
    } catch (d) {
        setBackupStatus(t("backup.error.exception") + " " + (d && d.message ? d.message : String(d)))
    }
}

var I18N = {
    en: {
        "app.name": "Recovery Mode WEBUI",
        "nav.basic": "Basic",
        "nav.advanced": "Advanced",
        "nav.firmware": "Firmware update",
        "nav.uboot": "U-Boot update",
        "nav.bl2": "BL2 update",
        "nav.gpt": "GPT update",
        "nav.factory": "Factory update",
        "nav.initramfs": "Load initramfs",
        "nav.system": "System",
        "nav.backup": "Backup",
        "nav.env": "Environment",
        "nav.console": "Console",
        "nav.reboot": "Reboot",
        "control.language": "🌐Language",
        "control.theme": "🌓Theme",
        "theme.auto": "Auto",
        "theme.light": "Light",
        "theme.dark": "Dark",
        "common.upload": "Upload",
        "common.update": "Update",
        "common.boot": "Boot",
        "common.warnings": "WARNINGS",
        "label.size": "Size: ",
        "label.md5": "MD5: ",
        "label.mtd": "MTD layout: ",
        "label.current_mtd": "Current mtd layout: ",
        "label.choose_mtd": "Choose mtd layout:",
        "index.title": "FIRMWARE UPDATE",
        "index.hint": "You are going to update <strong>firmware<\/strong> on the device.<br>Please, choose file from your local hard drive and click <strong>Upload<\/strong> button.",
        "index.upgrade_hint": 'If all information above is correct, click "Update".',
        "index.warn.1": "do not power off the device during update",
        "index.warn.2": "if everything goes well, the device will restart",
        "index.warn.3": "you can upload whatever you want, so be sure that you choose proper firmware image for your device",
        "uboot.title": "U-BOOT UPDATE",
        "uboot.hint": "You are going to update <strong>U-Boot (bootloader)<\/strong> on the device.<br>Please, choose file from your local hard drive and click <strong>Upload<\/strong> button.",
        "uboot.upgrade_hint": 'If all information above is correct, click "Update".',
        "uboot.warn.1": "do not power off the device during update",
        "uboot.warn.2": "if everything goes well, the device will restart",
        "uboot.warn.3": "you can upload whatever you want, so be sure that you choose proper U-Boot image for your device",
        "uboot.warn.4": "updating U-Boot is a very dangerous operation and may damage your device!",
        "bl2.title": "BL2 UPDATE",
        "bl2.hint": "You are going to update <strong>BL2 (preloader)<\/strong> on the device.<br>Please, choose file from your local hard drive and click <strong>Upload<\/strong> button.",
        "bl2.upgrade_hint": 'If all information above is correct, click "Update".',
        "bl2.warn.1": "do not power off the device during update",
        "bl2.warn.2": "if everything goes well, the device will restart",
        "bl2.warn.3": "you can upload whatever you want, so be sure that you choose proper BL2 image for your device",
        "bl2.warn.4": "updating BL2 is a very dangerous operation and may damage your device!",
        "gpt.title": "GPT UPDATE",
        "gpt.hint": "You are going to update <strong>GPT (Partition Table)<\/strong> on the device.<br>Please, choose file from your local hard drive and click <strong>Upload<\/strong> button.",
        "gpt.upgrade_hint": 'If all information above is correct, click "Update".',
        "gpt.warn.1": "do not power off the device during update",
        "gpt.warn.2": "if everything goes well, the device will restart",
        "gpt.warn.3": "you can upload whatever you want, so be sure that you choose proper GPT for your device",
        "gpt.warn.4": "updating GPT is a dangerous operation and may damage your device!",
        "factory.title": "FACTORY UPDATE",
        "factory.hint": "You are going to update <strong>Factory (Wireless Calibration)</strong> partition on the device.<br>Please, choose file from your local hard drive and click <strong>Upload</strong> button.",
        "factory.upgrade_hint": 'If all information above is correct, click "Update".',
        "factory.warn.1": "do not power off the device during update",
        "factory.warn.2": "if everything goes well, the device will restart",
        "factory.warn.3": "updating factory partition may damage your device or break calibration data",
        "reboot.confirm": "Reboot device now?",
        "reboot.title.in_progress": "REBOOTING DEVICE",
        "reboot.info.in_progress": "Reboot request has been sent. Please wait...<br>This page may be in not responding status for a short time.",
        "backup.title": "BACKUP",
        "backup.hint": "Download a backup from device storage as a <strong>binary file<\/strong>.<br>The backup data will be streamed to your browser and saved on your computer.",
        "backup.label.mode": "Mode:",
        "backup.label.target": "Target:",
        "backup.label.start": "Start:",
        "backup.label.end": "End (exclusive):",
        "backup.mode.part": "Partition backup",
        "backup.mode.range": "Custom range",
        "backup.action.download": "Download",
        "backup.warn.1": "do not power off the device during backup",
        "backup.warn.2": "custom range reads raw bytes; be careful with offsets",
        "backup.warn.3": "large backups may take a long time depending on storage speed",
        "backup.storage.not_present": "not present",
        "backup.target.placeholder": "-- select --",
        "backup.target.full_disk": "Full flash",
        "backup.range.hint": "Tip: input supports decimal, 0xHEX, and KiB suffix (e.g. 64KiB).",
        "backup.status.starting": "Starting...",
        "backup.status.downloading": "Downloading:",
        "backup.status.preparing": "Preparing file...",
        "backup.status.done": "Done:",
        "backup.error.no_target": "Please select a target",
        "backup.error.bad_range": "Please input valid start/end",
        "backup.error.http": "HTTP error:",
        "backup.error.exception": "Failed:",
        "sysinfo.loading": "Loading system info...",
        "sysinfo.unknown": "unknown",
        "sysinfo.cpu": "CPU:",
        "sysinfo.board": "Board:",
        "sysinfo.ram": "RAM:",
        "sysinfo.freq": "CPU Freq:",
        "sysinfo.partitions": "Partitions:",
        "sysinfo.current_layout": "Current layout:",
        "sysinfo.none": "none",
        "console.title": "WEB CONSOLE",
        "console.hint": "Run <strong>U-Boot commands<\/strong> directly in your browser.<br>Output is streamed by polling (no WebSocket). Treat this as <strong>root access<\/strong>.",
        "console.send": "Send",
        "console.clear": "Clear",
        "console.warn.1": "This console can execute arbitrary U-Boot commands.",
        "console.warn.2": "Do not expose this page on untrusted networks.",
        "console.warn.3": "If you set env failsafe_console_token, enter it above to unlock.",
        "console.status.ready": "Ready.",
        "console.status.running": "Running...",
        "console.status.done": "Done.",
        "console.status.cleared": "Cleared.",
        "console.status.ret": "Return:",
        "console.status.http": "HTTP error:",
        "console.status.parse": "Parse error.",
        "console.status.error": "Error:",
        "console.placeholder.token": "token (optional)",
        "console.placeholder.cmd": "help; printenv; mtd list",
        "env.title": "U-BOOT ENV",
        "env.hint": "Manage <strong>U-Boot environment variables<\/strong>. Changes will be saved to storage.",
        "env.section.list": "Environment variables",
        "env.label.name": "Name:",
        "env.label.value": "Value:",
        "env.label.file": "Env file:",
        "env.action.refresh": "Refresh",
        "env.action.set": "Add / Update",
        "env.action.unset": "Delete",
        "env.action.reset": "Reset to defaults",
        "env.action.restore": "Restore",
        "env.count": "Count:",
        "env.restore.hint": "Restore expects a binary U-Boot environment image (CRC + data).",
        "env.warn.1": "Modifying environment variables may affect boot behavior.",
        "env.warn.2": "Do not power off during save or restore.",
        "env.confirm.reset": "Reset environment to defaults?",
        "env.confirm.delete": "Delete variable",
        "env.confirm.restore": "Restore environment from file?",
        "env.status.ready": "Ready.",
        "env.status.loading": "Loading...",
        "env.status.saving": "Saving...",
        "env.status.saved": "Saved.",
        "env.status.deleted": "Deleted.",
        "env.status.reset": "Reset done.",
        "env.status.restored": "Restored.",
        "env.status.http": "HTTP error:",
        "env.status.error": "Error:",
        "env.error.no_name": "Please input a variable name",
        "env.error.no_file": "Please select an env file",
        "initramfs.title": "LOAD INITRAMFS",
        "initramfs.hint": "You are going to load <strong>initramfs<\/strong> on the device.<br>Please, choose file from your local hard drive and click <strong>Upload<\/strong> button.",
        "initramfs.boot_hint": 'If all information above is correct, click "Boot".',
        "initramfs.warn.1": "if everything goes well, the device will boot into the initramfs",
        "initramfs.warn.2": "you can upload whatever you want, so be sure that you choose proper initramfs image for your device",
        "flashing.title.in_progress": "UPDATE IN PROGRESS",
        "flashing.info.in_progress": "Your file was successfully uploaded! Update is in progress and you should wait for automatic reset of the device.<br>Update time depends on image size and may take up to a few minutes.",
        "flashing.title.done": "UPDATE COMPLETED",
        "flashing.info.done": "Your device was successfully updated! Now rebooting...",
        "booting.title.in_progress": "BOOTING INITRAMFS",
        "booting.info.in_progress": "Your file was successfully uploaded! Booting is in progress, please wait...<br>This page may be in not responding status for a short time.",
        "booting.title.done": "BOOT SUCCESS",
        "booting.info.done": "Your device was successfully booted into initramfs!",
        "fail.title": "UPDATE FAILED",
        "fail.msg.strong": "Something went wrong during update",
        "fail.msg.rest": "Probably you have chosen wrong file. Please, try again or contact with the author of this modification. You can also get more information during update in U-Boot console.",
        "404.title": "PAGE NOT FOUND",
        "404.msg": "The page you were looking for doesn't exist!"
    },
    "zh-cn": {
        "app.name": "恢复模式 WEBUI",
        "nav.basic": "基础功能",
        "nav.advanced": "高级功能",
        "nav.firmware": "固件升级",
        "nav.uboot": "更新 U-Boot",
        "nav.bl2": "更新 BL2",
        "nav.gpt": "更新 GPT",
        "nav.factory": "更新 Factory",
        "nav.initramfs": "加载 Initramfs",
        "nav.system": "系统",
        "nav.backup": "备份",
        "nav.env": "环境",
        "nav.console": "终端",
        "nav.reboot": "重启",
        "control.language": "🌐语言",
        "control.theme": "🌓主题",
        "theme.auto": "自动",
        "theme.light": "亮色",
        "theme.dark": "暗色",
        "common.upload": "上传",
        "common.update": "更新",
        "common.boot": "启动",
        "common.warnings": "注意事项",
        "label.size": "大小：",
        "label.md5": "MD5：",
        "label.mtd": "MTD 布局：",
        "label.current_mtd": "当前 mtd 布局：",
        "label.choose_mtd": "选择 mtd 布局：",
        "index.title": "固件升级",
        "index.hint": "你将要在设备上更新 <strong>固件<\/strong>。<br>请选择本地文件并点击 <strong>上传<\/strong> 按钮。",
        "index.upgrade_hint": "如果以上信息确认无误，请点击“更新”。",
        "index.warn.1": "升级过程中请勿断电",
        "index.warn.2": "如果一切顺利，设备会自动重启",
        "index.warn.3": "你可以上传任意文件，请确保选择了与你的设备匹配的固件镜像",
        "uboot.title": "U-Boot 刷写",
        "uboot.hint": "你将要在设备上更新 <strong>U-Boot（引导程序）<\/strong>。<br>请选择本地文件并点击 <strong>上传<\/strong> 按钮。",
        "uboot.upgrade_hint": "如果以上信息确认无误，请点击“更新”。",
        "uboot.warn.1": "刷写过程中请勿断电",
        "uboot.warn.2": "如果一切顺利，设备会自动重启",
        "uboot.warn.3": "你可以上传任意文件，请确保选择了与你的设备匹配的 U-Boot 镜像",
        "uboot.warn.4": "刷写 U-Boot 风险极高，可能导致设备损坏！",
        "bl2.title": "BL2 更新",
        "bl2.hint": "你将要在设备上更新 <strong>BL2（预加载器）<\/strong>。<br>请选择本地文件并点击 <strong>上传<\/strong> 按钮。",
        "bl2.upgrade_hint": "如果以上信息确认无误，请点击“更新”。",
        "bl2.warn.1": "刷写过程中请勿断电",
        "bl2.warn.2": "如果一切顺利，设备会自动重启",
        "bl2.warn.3": "你可以上传任意文件，请确保选择了与你的设备匹配的 BL2 镜像",
        "bl2.warn.4": "更新 BL2 风险极高，可能导致设备损坏！",
        "gpt.title": "GPT 分区表更新",
        "gpt.hint": "你将要在设备上更新 <strong>GPT（分区表）<\/strong>。<br>请选择本地文件并点击 <strong>上传<\/strong> 按钮。",
        "gpt.upgrade_hint": "如果以上信息确认无误，请点击“更新”。",
        "gpt.warn.1": "刷写过程中请勿断电",
        "gpt.warn.2": "如果一切顺利，设备会自动重启",
        "gpt.warn.3": "你可以上传任意文件，请确保选择了与你的设备匹配的 GPT",
        "gpt.warn.4": "更新 GPT 有风险，可能导致设备损坏！",
        "factory.title": "Factory 分区更新",
        "factory.hint": "你将要在设备上更新 <strong>Factory(无线校准)</strong> 分区。<br>请选择本地文件并点击 <strong>上传</strong> 按钮。",
        "factory.upgrade_hint": "如果以上信息确认无误，请点击“更新”。",
        "factory.warn.1": "刷写过程中请勿断电",
        "factory.warn.2": "如果一切顺利，设备会自动重启",
        "factory.warn.3": "更新 factory 分区风险极高，可能破坏校准数据并导致设备异常！",
        "reboot.confirm": "确认立即重启设备？",
        "reboot.title.in_progress": "正在重启设备…",
        "reboot.info.in_progress": "已发送重启请求，请稍候…<br>该页面短时间可能显示无响应，这是正常现象。",
        "backup.title": "备份",
        "backup.hint": "从设备存储中导出备份并保存为<strong>二进制文件<\/strong>。<br>备份数据将以流式方式传输到浏览器，并保存在你的电脑上。",
        "backup.label.mode": "模式：",
        "backup.label.target": "目标：",
        "backup.label.start": "起始：",
        "backup.label.end": "结束（不包含）：",
        "backup.mode.part": "分区备份",
        "backup.mode.range": "自定义范围",
        "backup.action.download": "下载",
        "backup.warn.1": "备份过程中请勿断电",
        "backup.warn.2": "自定义范围读取原始字节，请谨慎设置偏移",
        "backup.warn.3": "大容量备份可能耗时较长，取决于存储速度",
        "backup.storage.not_present": "未检测到",
        "backup.target.placeholder": "-- 请选择 --",
        "backup.target.full_disk": "全盘备份",
        "backup.range.hint": "提示：支持十进制、0x 十六进制，以及 KiB 后缀（例如 64KiB）。",
        "backup.status.starting": "开始中…",
        "backup.status.downloading": "下载中：",
        "backup.status.preparing": "正在生成文件…",
        "backup.status.done": "完成：",
        "backup.error.no_target": "请选择一个目标",
        "backup.error.bad_range": "请输入有效的起始/结束",
        "backup.error.http": "HTTP 错误：",
        "backup.error.exception": "失败：",
        "sysinfo.loading": "正在获取系统信息…",
        "sysinfo.unknown": "未知",
        "sysinfo.cpu": "处理器：",
        "sysinfo.board": "板卡：",
        "sysinfo.ram": "内存：",
        "sysinfo.freq": "CPU 频率：",
        "sysinfo.partitions": "分区表：",
        "sysinfo.current_layout": "当前布局：",
        "sysinfo.none": "无",
        "console.title": "网页终端",
        "console.hint": "在浏览器中直接执行 <strong>U-Boot 命令<\/strong>。<br>输出通过轮询方式获取（非 WebSocket），相当于 <strong>root 权限<\/strong>。",
        "console.send": "发送",
        "console.clear": "清空",
        "console.warn.1": "该终端可执行任意 U-Boot 命令。",
        "console.warn.2": "不要在不可信网络中暴露此页面。",
        "console.warn.3": "如设置了环境变量 failsafe_console_token，请在上方输入以解锁。",
        "console.status.ready": "就绪。",
        "console.status.running": "执行中...",
        "console.status.done": "完成。",
        "console.status.cleared": "已清空。",
        "console.status.ret": "返回值：",
        "console.status.http": "HTTP 错误：",
        "console.status.parse": "解析失败。",
        "console.status.error": "错误：",
        "console.placeholder.token": "token（可选）",
        "console.placeholder.cmd": "help; printenv; mtd list",
        "env.title": "U-Boot 环境变量",
        "env.hint": "管理 <strong>U-Boot 环境变量<\/strong>，修改会保存到存储。",
        "env.section.list": "环境变量列表",
        "env.label.name": "名称：",
        "env.label.value": "值：",
        "env.label.file": "环境文件：",
        "env.action.refresh": "刷新",
        "env.action.set": "新增/更新",
        "env.action.unset": "删除",
        "env.action.reset": "重置为默认",
        "env.action.restore": "恢复",
        "env.count": "数量：",
        "env.restore.hint": "恢复需要 U-Boot 环境二进制镜像（含 CRC）。",
        "env.warn.1": "修改环境变量可能影响启动行为。",
        "env.warn.2": "保存或恢复过程中请勿断电。",
        "env.confirm.reset": "确认重置为默认环境？",
        "env.confirm.delete": "删除变量",
        "env.confirm.restore": "确认从文件恢复环境？",
        "env.status.ready": "就绪。",
        "env.status.loading": "加载中…",
        "env.status.saving": "保存中…",
        "env.status.saved": "已保存。",
        "env.status.deleted": "已删除。",
        "env.status.reset": "已重置。",
        "env.status.restored": "已恢复。",
        "env.status.http": "HTTP 错误：",
        "env.status.error": "错误：",
        "env.error.no_name": "请输入变量名称",
        "env.error.no_file": "请选择环境文件",
        "initramfs.title": "启动 Initramfs",
        "initramfs.hint": "你将要在设备上加载 <strong>initramfs<\/strong>。<br>请选择本地文件并点击 <strong>上传<\/strong> 按钮。",
        "initramfs.boot_hint": "如果以上信息确认无误，请点击“启动”。",
        "initramfs.warn.1": "如果一切顺利，设备将进入 initramfs",
        "initramfs.warn.2": "你可以上传任意文件，请确保选择了与你的设备匹配的 initramfs 镜像",
        "flashing.title.in_progress": "正在刷写…",
        "flashing.info.in_progress": "文件上传成功！正在执行刷写，请等待设备自动重启。<br>刷写时间取决于镜像大小，可能需要几分钟。",
        "flashing.title.done": "刷写完成",
        "flashing.info.done": "设备已成功更新！即将重启…",
        "booting.title.in_progress": "正在启动 Initramfs…",
        "booting.info.in_progress": "文件上传成功！正在启动，请稍候…<br>该页面短时间可能显示无响应，这是正常现象。",
        "booting.title.done": "启动成功",
        "booting.info.done": "设备已成功进入 initramfs！",
        "fail.title": "更新失败",
        "fail.msg.strong": "更新过程中出现错误",
        "fail.msg.rest": "可能选择了错误的文件。请重试或联系此修改的作者。你也可以在 U-Boot 控制台查看更多刷写过程信息。",
        "404.title": "页面不存在",
        "404.msg": "你访问的页面不存在！"
    }
};

APP_STATE = {
    lang: "en",
    theme: "auto",
    page: ""
}