const ctx = document.getElementById('graph').getContext('2d');
const chart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: [],  // Time labels or any other labels you wish
        datasets: [{
            label: 'Packet Count (TCP, UDP, ICMP)',
            data: [],  // Empty initially
            borderColor: 'rgb(75, 192, 192)',
            tension: 0.1
        }]
    }
});

function updateChart() {
    fetch('/graph-data')  // Fetching data from the Flask route
        .then(response => response.json())
        .then(data => {
            const totalCount = data.tcp + data.udp + data.icmp;  // Summing the counts of protocols

            chart.data.labels.push(new Date().toLocaleTimeString());  // Add current time as label
            chart.data.datasets[0].data.push(totalCount);  // Add total count to the data array
            chart.update();  // Update the chart with new data
        })
        .catch(error => {
            console.error('Error fetching graph data:', error);  // Handle any error in fetching
        });
}

// Update the chart every 2 seconds
setInterval(updateChart, 2000);
