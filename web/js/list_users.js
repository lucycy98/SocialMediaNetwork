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

loadOnline()

var myVar = setInterval(loadOnline, 9000);