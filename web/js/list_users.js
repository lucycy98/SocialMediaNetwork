var last_clicked_username = null;

function refreshInfo() {
	$.ajax({
		url: "/message"
	  })
	  .done(function() {
		$("#all_users").load(location.href+" #all_users>*","");
	  });
  }
  //Update list of users every x seconds
  refreshInfo()
  var interval = setInterval(refreshInfo, 10000);


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
			//time = messageObj.sender_created_at;
			date = new Date(messageObj.sender_created_at * 1000);
			time = formatDate(date);
			if (received == "sent"){
				Page += "<li><div class='blue_box'><span>" + messageObj.message + "</span></div></li>";
				Page +="<li><div class='time-right'><span>" + time + "</span></div></li>";
			} else {
				Page += "<li><div class='green_box'><span>" + messageObj.message + "</span></div></li>";
				Page +="<li><div class='time-left'><span>" + time + "</span></div></li>";
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

function formatDate(date) {
	var hours = date.getHours();
	var minutes = date.getMinutes();
	var ampm = hours >= 12 ? 'pm' : 'am';
	hours = hours % 12;
	hours = hours ? hours : 12; // the hour '0' should be '12'
	minutes = minutes < 10 ? '0'+minutes : minutes;
	var strTime = hours + ':' + minutes + ' ' + ampm;
	return date.getDate() +'/'+ (date.getMonth()+1) + '/' + date.getFullYear() +"  " + strTime;
  }

//loadOnline()
report()
getParam()

//var myVar2 = setInterval(loadOnline, 11600);
var myvar = setInterval(report, 11000);