function favouriteBroadcast(id) {

  var xhttp = new XMLHttpRequest();
  var urlString = "favouriteBroadcast?signature=" + id;
  xhttp.open("GET", urlString, true);
  xhttp.timeout = 8000;
  xhttp.send(null);
  refreshPage(window.location.pathname)
}

function blockBroadcast(id) {

  var xhttp = new XMLHttpRequest();
  var urlString = "blockBroadcast?signature=" + id;
  xhttp.open("GET", urlString, true);
  xhttp.timeout = 8000;
  xhttp.send(null);
  refreshPage(window.location.pathname)
}

/* When the user clicks on the button, 
toggle between hiding and showing the dropdown content */
function clickFilter() {
  document.getElementById("myFilter").classList.toggle("show");
}

function refreshPage(urlstring) {
	$.ajax({
		url: urlstring
	  })
	  .done(function() {
		$("#container").load(location.href+" #container>*","");
	  });
  }  

// Close the dropdown menu if the user clicks outside of it
window.onclick = function (event) {
  if (!event.target.matches('.filterbtn')) {
    var dropdowns = document.getElementsByClassName("filter-content");
    var i;
    for (i = 0; i < dropdowns.length; i++) {
      var openDropdown = dropdowns[i];
      if (openDropdown.classList.contains('show')) {
        openDropdown.classList.remove('show');
      }
    }
  }
}