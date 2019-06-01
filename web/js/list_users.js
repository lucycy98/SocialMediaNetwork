function loadOnline() {
    document.getElementById("all_users").innerHTML = "hi";
	var xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = function() {
	if (this.readyState == 4 && this.status == 200) {
		var obj = JSON.parse(this.response)
		document.getElementById("all_users").innerHTML = "hi";
		}
	};
	xhttp.open("GET", "storeUsers", true);
	xhttp.timeout = 8000;
	xhttp.send(null); 
}

loadOnline()

var myVar = setInterval(loadOnline, 8000);