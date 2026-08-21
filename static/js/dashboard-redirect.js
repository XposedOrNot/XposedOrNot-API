(function () {
  var seconds = 5;
  var el = document.getElementById('countdown');
  var url = document.getElementById('dashboard-link').href;
  var timer = setInterval(function () {
    seconds--;
    el.textContent = seconds;
    if (seconds <= 0) {
      clearInterval(timer);
      window.location.href = url;
    }
  }, 1000);
})();
