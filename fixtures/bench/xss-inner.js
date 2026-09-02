// 真实性基准：XSS
function render(userHtml) {
  document.getElementById('app').innerHTML = userHtml; // 行 4 应命中
}
