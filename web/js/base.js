function report() {
	var xhttp = new XMLHttpRequest();
	xhttp.open("GET", "reportUser?status=online", true);
	xhttp.timeout = 8000;
	xhttp.send(null); 
}

report()
var myvar = setInterval(report, 30000);