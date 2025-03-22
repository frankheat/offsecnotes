// Icon collapse

function toggleRotation(element) {
    const svg = element.querySelector("svg");

    const transform = svg.getAttribute("transform");
    svg.style.transition = "transform 0.3s ease-in-out";
    if (transform && transform.includes("rotate(90)")) {
        svg.setAttribute("transform", "rotate(0)");
    } else {
        svg.setAttribute("transform", "rotate(90)");
    }
}