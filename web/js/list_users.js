function loadOnline() {
	var xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = function() {
        
	if (this.readyState == 4 && this.status == 200) {
		var obj = JSON.parse(this.response)
		document.getElementById("all_users").innerHTML = obj.all_users;
		}
	};
	xhttp.open("GET", "listActiveUsers", true);
	xhttp.timeout = 8000;
	xhttp.send(null); 
}

function report() {
	var xhttp = new XMLHttpRequest();
	xhttp.open("GET", "reportUser?status=online", true);
	xhttp.timeout = 8000;
	xhttp.send(null); 
}

function retrieveMessages() {
	var xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = function() {
        
	if (this.readyState == 4 && this.status == 200) {
		var obj = JSON.parse(this.response)
		document.getElementById("message-header").innerHTML = obj.all_users;
		}
	};
	xhttp.open("GET", "listActiveUsers", true);
	xhttp.timeout = 8000;
	xhttp.send(null); 

}

loadOnline()
report()

var myVar = setInterval(loadOnline, 9000);
var myVar2 = setInterval(report, 1000);