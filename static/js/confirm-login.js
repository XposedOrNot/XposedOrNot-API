(function () {
  var seconds = 5;
  var el = document.getElementById('countdown');
  var form = document.getElementById('confirm-form');
  var timer = setInterval(function () {
    seconds--;
    el.textContent = seconds;
    if (seconds <= 0) {
      clearInterval(timer);
      form.submit();
    }
  }, 1000);
})();
