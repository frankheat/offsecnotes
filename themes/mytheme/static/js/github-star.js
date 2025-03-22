fetch('https://api.github.com/repos/francescovolpe/offsecnotes')
    .then(response => response.json())
    .then(data => {
        document.getElementById('star-count').textContent = data.stargazers_count;
    })
    .catch(error => console.error('Errore nel recupero delle stelle:', error));