fetch('https://vt.frankheat.io/?vfref=' + encodeURIComponent(window.location.href), {
    method: 'GET',
    mode: 'no-cors'
});