(function () {
  function pad(number) {
    return String(number).padStart(2, "0");
  }

  function tick() {
    var now = Math.floor(Date.now() / 1000);
    var remaining = 30 - (now % 30);
    document.querySelectorAll("[data-totp-countdown]").forEach(function (node) {
      node.textContent = pad(remaining) + "s";
    });
  }

  tick();
  window.setInterval(tick, 1000);
})();
