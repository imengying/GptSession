import init from "/assets/session_bridge_web.js";

try {
  await init();
} catch {
  const status = document.querySelector("#input-status");
  if (status) {
    status.classList.add("is-error");
    status.textContent = "当前浏览器不支持 WebAssembly memory64，请升级浏览器后重试。";
  }
  document.querySelectorAll("button, textarea").forEach((element) => {
    element.disabled = true;
  });
}
