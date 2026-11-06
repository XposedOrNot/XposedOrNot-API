(function () {
  var form = document.getElementById('confirm-form');
  var button = form.querySelector('button[type="submit"]');
  var submitted = false;

  form.addEventListener('submit', function (event) {
    if (submitted) {
      event.preventDefault();
      return;
    }
    submitted = true;
    if (button) {
      button.disabled = true;
    }
  });
})();
