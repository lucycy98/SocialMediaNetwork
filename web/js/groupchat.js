$(document).ready(function () {
  $("#groupchat-btn").click(function () {
    alert("Creating group chats, please wait while this occurs.")
    var names = [];
    $.each($("input[name='username']:checked"), function () {
      names.push($(this).val());
    });
    alert("Creating group chats, please wait while this occurs.")
    makeGroupChat(names)
    //location.reload()
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
  var data = JSON.stringify({ "names": names });
  xhr.send(data);
}

// Get the modal
var modal = document.getElementById("myModal");

// Get the button that opens the modal
var btn = document.getElementById("myBtn");

// Get the <span> element that closes the modal
var span = document.getElementsByClassName("close")[0];

// When the user clicks on the button, open the modal 
btn.onclick = function () {
  modal.style.display = "block";
  //loadPeopldsName()
}

// When the user clicks on <span> (x), close the modal
span.onclick = function () {
  modal.style.display = "none";
}

// When the user clicks anywhere outside of the modal, close it
window.onclick = function (event) {
  if (event.target == modal) {
    modal.style.display = "none";
  }
}




