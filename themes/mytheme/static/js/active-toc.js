// Manage active content in the toc

document.addEventListener("DOMContentLoaded", function () {
    let tocLinks = document.querySelectorAll("#TableOfContents a");
    let sections = document.querySelectorAll("h2, h3");

    window.addEventListener("scroll", function () {
        let currentSection = "";
        let offset = 61;

        sections.forEach(section => {
            let sectionTop = section.getBoundingClientRect().top + window.scrollY;
            if (window.scrollY >= sectionTop - offset) {
                currentSection = section.getAttribute("id");
            }
        });

        tocLinks.forEach(link => {
            link.classList.remove("active");
            if (link.getAttribute("href").substring(1) === currentSection) {
                link.classList.add("active");
            }
        });
    });
});