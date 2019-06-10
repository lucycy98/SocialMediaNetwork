function refreshInfo() {
	$.ajax({
		url: "/message"
	})
		.done(function () {
			$("#all_users").load(location.href + " #all_users>*", "");
			$("#pm").load(location.href + " #pm>*", "");
		});
}
//Update list of users every x seconds
refreshInfo()
var interval2 = setInterval(refreshInfo, 10000);

var last_clicked_username = null;

function checkSize() {
	message = document.getElementById('msg').value
	alert(message.length)
	if (message.length > 1024) {
		alert("message cannot exceed 1024 characters!")
		return false;
	} else if (message.length == 0) {
		alert("message cannot be empty!")
		return false;
	}
	return true;
}



function getParam() {
	var url = new URL(window.location.href);
	var c = url.searchParams.get("name");
	if (c != null){
		document.getElementById('targetuser').value = c;
	}
}


function formatDate(date) {
	var hours = date.getHours();
	var minutes = date.getMinutes();
	var ampm = hours >= 12 ? 'pm' : 'am';
	hours = hours % 12;
	hours = hours ? hours : 12; // the hour '0' should be '12'
	minutes = minutes < 10 ? '0' + minutes : minutes;
	var strTime = hours + ':' + minutes + ' ' + ampm;
	return date.getDate() + '/' + (date.getMonth() + 1) + '/' + date.getFullYear() + "  " + strTime;
}


getParam()