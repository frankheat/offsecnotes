// Tooglesidebar
function changeClass(element, firstClass, secondClass) {
    let div = document.getElementById(element);
    if (div.classList.contains(firstClass)) {
        div.classList.replace(firstClass, secondClass);
    } else {
        div.classList.replace(secondClass, firstClass);
    }
}

document.getElementById('toggleSidebar').addEventListener('click', function () {
    document.getElementById('sidebarLeft').classList.toggle('d-none');
    document.getElementById('sidebarLeft').classList.toggle('d-lg-none');
    changeClass('mainContent', 'col-xl-6', 'col-xl-7');

    if (window.innerWidth < 992 && !document.getElementById('sidebarLeft').classList.contains('d-none') ) {
        window.scrollTo({
            top: 0,
            left: 0,
            behavior: 'instant'
        });
    }
});

