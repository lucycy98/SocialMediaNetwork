var last_clicked_username = null;

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
				Page += "<li><a id='" + username + "' href='#' onclick='clickfuncMessage(this.id)'>"+status +  " " + username +"</a></li>";
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

function getParam(){
	var url = new URL(window.location.href);
	var c = url.searchParams.get("name");
	document.getElementById('targetuser').value = c;
}

function clickfuncMessage(object) {
	last_clicked_username = object;
	document.getElementById("msgheader").innerHTML = "<a href='/profile?name=" + last_clicked_username+ "'>" + last_clicked_username + "</a>"
	document.getElementById('targetuser').value = last_clicked_username;
	retrievePrivateMessages(last_clicked_username)
}

function refreshMessages() {
	retrievePrivateMessages(last_clicked_username);
}

function retrievePrivateMessages(username) {
	var xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = function() {
		
	if (this.readyState == 4 && this.status == 200) {
		var obj = JSON.parse(this.response)
		var messages = obj["data"];
		Page = ""
		if (messages.length == 0){
			Page += "Start a conversation with "
			Page += username
			document.getElementById("pm").innerHTML = Page;
		}

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
getParam()

var myVar2 = setInterval(loadOnline, 11600);
var myvar = setInterval(report, 11000);