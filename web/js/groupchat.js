// Get the modal
var modal = document.getElementById("myModal");

// Get the button that opens the modal
var btn = document.getElementById("myBtn");

// Get the <span> element that closes the modal
var span = document.getElementsByClassName("close")[0];

// When the user clicks on the button, open the modal 
btn.onclick = function() {
  modal.style.display = "block";
  //loadPeopldsName()
}

// When the user clicks on <span> (x), close the modal
span.onclick = function() {
  modal.style.display = "none";
}

// When the user clicks anywhere outside of the modal, close it
window.onclick = function(event) {
  if (event.target == modal) {
    modal.style.display = "none";
  }
}

$(document).ready(function() {
    $("button").click(function(){
        var names = [];
        $.each($("input[name='username']:checked"), function(){            
            names.push($(this).val());
        });
        //document.getElementById("hello").innerHTML = names.join(", ");
        makeGroupChat(names)
    });
});

function makeGroupChat(names) {
	xhr = new XMLHttpRequest();
    xhr.open("POST", "createGroupChat", true);
    xhr.setRequestHeader("Content-type", "application/json");
    xhr.onreadystatechange = function () { 
        if (xhr.readyState == 4 && xhr.status == 200) {
            var json = JSON.parse(xhr.responseText);
        }
    }
    var data = JSON.stringify({"names": names});
    xhr.send(data);
}

function loadPeopldsName() {
	var xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = function() {
        
	if (this.readyState == 4 && this.status == 200) {
		var obj = JSON.parse(this.response)
		Page = ""

		for (var key in obj) { 
			if (obj.hasOwnProperty(key)) {
                username = key
                Page += "<li><label><input type='checkbox' value='" + username +"' name='username'><span></span>" + username + "</label></li>"
                //Page += "<tr><td class = 'username-td'>" + username + "</td><td class = 'box-td'><input type='checkbox' value='" + username +"' name='username'></td></tr>"
			}
		}
		document.getElementById("group-list").innerHTML = Page;
		}
	};
	xhttp.open("GET", "listActiveUsers", true);
	xhttp.timeout = 8000;
	xhttp.send(null); 
}