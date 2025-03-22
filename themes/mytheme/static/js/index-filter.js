// Index filter

const input = document.getElementById('filter-input');
input.addEventListener('input', function () {

    const filter = input.value.toLowerCase().trim();
    const collapseElements = document.querySelectorAll('#index .collapse');
    collapseElements.forEach(el => {
        let collapseInstance = bootstrap.Collapse.getInstance(el);
        if (!collapseInstance) {
            collapseInstance = new bootstrap.Collapse(el, { toggle: false });
        }
        if (filter === "") {
            collapseInstance.hide();
            sessionStorage.setItem('resetCollapse', "false");

            const span = document.getElementById(el.id + "-icon");
            const svg = span.querySelector("svg");
            svg.style.transition = "transform 0.3s ease-in-out";
            svg.setAttribute("transform", "rotate(0)");
        } else {
            collapseInstance.show();
            sessionStorage.setItem('resetCollapse', "true");

            const span = document.getElementById(el.id + "-icon");
            const svg = span.querySelector("svg");
            svg.style.transition = "transform 0.3s ease-in-out";
            svg.setAttribute("transform", "rotate(90)");
        }
    });

    const listItems = document.querySelectorAll('#index ul li');
    listItems.forEach(item => {
        const text = item.textContent.toLowerCase();

        if (text.includes(filter)) {
            item.style.display = '';
        } else {
            item.style.display = 'none';
        }

    });
});