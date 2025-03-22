document.addEventListener('DOMContentLoaded', function () {
    
    if (sessionStorage.getItem('resetCollapse') === 'true') {
        sessionStorage.removeItem('sidebarState');
        sessionStorage.removeItem('resetCollapse');
    }
    const sidebarState = JSON.parse(sessionStorage.getItem('sidebarState')) || {};

    // Restore the open sections status
    Object.keys(sidebarState).forEach(function (id) {
        if (sidebarState[id] === true) {
            const collapseElem = document.getElementById(id);
            if (collapseElem) {
                collapseElem.classList.add('show');

                const span = document.getElementById(id+"-icon");
                const svg = span.querySelector("svg");
                svg.setAttribute("transform", "rotate(90)");
            }
        }
    });

    const collapseElements = document.querySelectorAll('.site-nav .collapse');

    // Add the event listener to update the status
    collapseElements.forEach(function (elem) {
        elem.addEventListener('shown.bs.collapse', function () {
            sidebarState[elem.id] = true;
            sessionStorage.setItem('sidebarState', JSON.stringify(sidebarState));
        });
        elem.addEventListener('hidden.bs.collapse', function () {
            sidebarState[elem.id] = false;
            sessionStorage.setItem('sidebarState', JSON.stringify(sidebarState));
        });
    });
});