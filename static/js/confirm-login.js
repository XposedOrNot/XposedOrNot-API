(function () {
  var seconds = 5;
  var el = document.getElementById('countdown');
  var form = document.getElementById('confirm-form');
  var button = form.querySelector('button[type="submit"]');
  var submitted = false;

  function lockForm() {
    submitted = true;
    clearInterval(timer);
    if (button) {
      button.disabled = true;
    }
  }

  var timer = setInterval(function () {
    seconds--;
    el.textContent = seconds;
    if (seconds <= 0) {
      lockForm();
      form.submit();
    }
  }, 1000);

  form.addEventListener('submit', function (event) {
    if (submitted) {
      event.preventDefault();
      return;
    }
    lockForm();
  });
})();
