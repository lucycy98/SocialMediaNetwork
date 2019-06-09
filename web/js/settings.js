// Create a "close" button and append it to each list item
var myNodelist = document.getElementsByTagName("LI");
var i;
for (i = 0; i < myNodelist.length; i++) {
    var span = document.createElement("SPAN");
    var txt = document.createTextNode("\u00D7");
    span.className = "close";
    span.appendChild(txt);
    myNodelist[i].appendChild(span);
}

// Click on a close button to hide the current list item
var close = document.getElementsByClassName("close");
var i;
for (i = 0; i < close.length; i++) {
    close[i].onclick = function () {
        variable = this.parentElement.id;
        deleteWord(variable)
    }
}

function refreshInfo() {
	$.ajax({
		url: "/settings"
	  })
	  .done(function() {
		$("#blocked-words").load(location.href+" #blocked-words>*","");
	  });
  }  


function deleteWord(word) {
    alert("DELETNG")
    xhr = new XMLHttpRequest();
    url = "settings?unblockWord="+word;
    xhr.open("GET", url, true);
    xhr.send(null);
    refreshInfo()
}


// Create a new list item when clicking on the "Add" button
function checkEmpty() {

    var inputValue = document.getElementById("block-input").value;
    
    if (inputValue === '') {
        alert("You must write something!");
        return false;
    }
    return true;
}

// Create a new list item when clicking on the "Add" button
function newElement() {
    var li = document.createElement("li");
    var inputValue = document.getElementById("block-input").value;
    var t = document.createTextNode(inputValue);
    li.appendChild(t);
    if (inputValue === '') {
        alert("You must write something!");
    } else {
        document.getElementById("myUL").appendChild(li);
    }
    document.getElementById("block-input").value = "";

    var span = document.createElement("SPAN");
    var txt = document.createTextNode("\u00D7");
    span.className = "close";
    span.appendChild(txt);
    li.appendChild(span);

    for (i = 0; i < close.length; i++) {
        close[i].onclick = function () {
            var div = this.parentElement;
            div.style.display = "none";
        }
    }
}