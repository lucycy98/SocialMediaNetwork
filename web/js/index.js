function loadBroadcasts() {
    var xhttp = new XMLHttpRequest();

	xhttp.onreadystatechange = function() {
        
	if (this.readyState == 4 && this.status == 200) {
        var obj = JSON.parse(this.response)

		Page = ""
        data = obj["data"]
        
        for (i=0; i < data.length; i++){
            tup = data[i];
            Page += "<div class='block_container'><div class='cont'><h3>" + tup.username + "<img class='vertical-align-img' src=img/block.svg style='width: 1em'></h3><p></p>" + tup.message + "</p> </br><img class='icons' src=img/like.svg style='width: 1.5em'></div></div>"
        }

		document.getElementById("newposts").innerHTML = Page;
		}
	};
	xhttp.open("GET", "getBroadcasts", true);
	xhttp.timeout = 8000;
	xhttp.send(null); 
}
loadBroadcasts()

var myVar2 = setInterval(loadBroadcasts, 8000);
