function loadOnline() {
	var xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = function() {
        
	if (this.readyState == 4 && this.status == 200) {
		var obj = JSON.parse(this.response)
		Page = ""

		for (var key in obj) { 
			if (obj.hasOwnProperty(key)) {
				username = key
				status = obj[username]
				Page += "<li><a id='" + username + "' href='#' onclick='clickfuncMessage(this.id)'>"+username+"</a> " + status + "</li>";
			}
		}
		document.getElementById("all_users").innerHTML = Page;
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

function clickfuncMessage(object) {
	document.getElementById("msgheader").innerHTML = object;
	document.getElementById('targetuser').value = object;
	retrievePrivateMessages(object)
}

function retrievePrivateMessages(username) {
	var xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = function() {
		
	if (this.readyState == 4 && this.status == 200) {
		var obj = JSON.parse(this.response)
		var messages = obj["data"];

		if (messages.length == 0){
			return;
		}

		Page = ""

		for (i=0; i < messages.length; i++){
			messageObj = messages[i];
			received = messageObj.sent;
			if (received == "sent"){
				Page += "<li><div class='blue_box'><span>" + messageObj.message + "</span></div></li>";
			} else {
				Page += "<li><div class='green_box'><span>" + messageObj.message + "</span></div></li>";
			}
		}
		document.getElementById("pm").innerHTML = Page;
		}
	};
	query = "getMessages?username=" + username;
	xhttp.open("GET", query, true);
	xhttp.timeout = 8000;
	xhttp.send(null); 

}

loadOnline()
report()

var myVar2 = setInterval(loadOnline, 11600);
var myvar = setInterval(report, 11000);