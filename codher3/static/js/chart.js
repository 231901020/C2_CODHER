const ctx = document.getElementById('graph').getContext('2d');
const chart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'Packet Count',
            data: [],
            borderColor: 'rgb(75, 192, 192)',
            tension: 0.1
        }]
    }
});

function updateChart() {
    fetch('/graph-data')
        .then(response => response.json())
        .then(data => {
            chart.data.labels.push(new Date().toLocaleTimeString());
            chart.data.datasets[0].data.push(data.count);
            chart.update();
        });
}

setInterval(updateChart, 2000);
