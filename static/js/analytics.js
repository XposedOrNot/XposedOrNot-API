window.dataLayer = window.dataLayer || [];

function gtag() {
  dataLayer.push(arguments);
}

(function () {
  var GA_MEASUREMENT_ID = 'G-MHXCCZ0EYY';
  var HOTJAR_ID = 1613245;
  var HOTJAR_SV = 6;
  var MAX_PUBLIC_SEGMENT = 20;

  function redactSegment(segment) {
    if (segment.indexOf('@') !== -1 || segment.indexOf('%40') !== -1) {
      return '{email}';
    }
    if (segment.length >= MAX_PUBLIC_SEGMENT) {
      return '{token}';
    }
    return segment;
  }

  function redactedPath() {
    return window.location.pathname.split('/').map(redactSegment).join('/');
  }

  var path = redactedPath();

  gtag('js', new Date());
  gtag('config', GA_MEASUREMENT_ID, {
    page_path: path,
    page_location: window.location.origin + path,
    page_title: document.title
  });

  (function (h, o, t, j, a, r) {
    h.hj =
      h.hj ||
      function () {
        (h.hj.q = h.hj.q || []).push(arguments);
      };
    h._hjSettings = { hjid: HOTJAR_ID, hjsv: HOTJAR_SV };
    a = o.getElementsByTagName('head')[0];
    r = o.createElement('script');
    r.async = 1;
    r.src = t + h._hjSettings.hjid + j + h._hjSettings.hjsv;
    a.appendChild(r);
  })(window, document, 'https://static.hotjar.com/c/hotjar-', '.js?sv=');
})();
