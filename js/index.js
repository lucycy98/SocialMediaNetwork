function loadOnline() {
	//document.getElementById("users").innerHTML = "hi"
	console.log("LOADING JAVASCRIPT")
	var xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = function() {
	if (this.readyState == 4 && this.status == 200) {
		
		var obj = JSON.parse(this.response)
		console.log("object is ")
		document.getElementById("users").innerHTML = obj.data;

		}
	};
	xhttp.open("GET", "listActiveUsers", true);
	xhttp.timeout = 8000;
	xhttp.send(null); 
}

loadOnline()

var myVar = setInterval(loadOnline, 8000);

