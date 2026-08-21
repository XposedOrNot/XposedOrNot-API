document.querySelectorAll(".term-copy").forEach(function (btn) {
    btn.addEventListener("click", function () {
        var text = btn.getAttribute("data-copy");
        if (!text || !navigator.clipboard) {
            return;
        }
        navigator.clipboard.writeText(text).then(function () {
            btn.textContent = "copied";
            setTimeout(function () {
                btn.textContent = "copy";
            }, 1500);
        });
    });
});
