function sendBlockData() {
	var url = new URL(window.location.href);
	var name = url.searchParams.get("name");
	var xhttp = new XMLHttpRequest();
	var urlString = "blockUser?username=" + name;
	xhttp.open("GET", urlString, true);
	xhttp.timeout = 8000;
	xhttp.send(null); 
}
