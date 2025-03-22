// Manage active content in the index

document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".site-nav a").forEach(function (link) {
        if (link.href === window.location.href) {
            link.classList.add("active");
        }
    });
});
