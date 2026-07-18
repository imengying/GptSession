import init from "/assets/session_bridge_web.js?v=20260718-4";

try {
  await init({
    module_or_path: "/assets/session_bridge_web_bg.wasm?v=20260718-4",
  });
} catch {
  const status = document.querySelector("#input-status");
  if (status) {
    status.classList.add("is-error");
    status.textContent =
      "前端组件加载失败，请刷新页面；若仍失败，请升级到支持 WebAssembly memory64 的浏览器。";
  }
  document.querySelectorAll("button, textarea").forEach((element) => {
    element.disabled = true;
  });
}
