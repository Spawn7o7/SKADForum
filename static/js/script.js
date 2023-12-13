function myFunction() {
    document.getElementById("myDropdown").classList.toggle("show");
}

// Close the dropdown menu if the user clicks outside of it
window.onclick = function(event) {
    if (!event.target.matches('.dropbtn')) {
        var dropdowns = document.getElementsByClassName("dropdown-content");
        var i;
        for (i = 0; i < dropdowns.length; i++) {
            var openDropdown = dropdowns[i];
            if (openDropdown.classList.contains('show')) {
                openDropdown.classList.remove('show');
            }
        }
    }
}

//Javascript for hiding the comment box
function showComment(){
    var commentArea = document.getElementById("commentarea");
    commentArea.setAttribute("style", 'display:block;');
}

function hideComment(){
    var commentArea = document.getElementById("commentarea");
    commentArea.setAttribute("style", 'display:none;');
}

//Javascript for hiding the reply box
function showReply(){
    var replyArea = document.getElementById("replyarea");
    replyArea.setAttribute("style", 'display:block;');
}

function hideReply(){
    var replyArea = document.getElementById("replyarea");
    replyArea.setAttribute("style", 'display:none;');
}

