function httpGetAsync(url, callback)
{
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.onreadystatechange = function() { 
        if (xmlHttp.readyState == 4 && xmlHttp.status == 200)
            callback(xmlHttp.responseText);
    }
    xmlHttp.open("GET", url, true); // true for asynchronous 
    xmlHttp.send(null);
}

function reportMalicious(e) {
  chrome.tabs.getSelected(function(tab) {
    var url = "http://ec2-35-163-58-17.us-west-2.compute.amazonaws.com:5001/report?url="+tab.url;
    var malDiv = document.getElementById("malicious");
    var thankDiv = document.getElementById("thankyou");
    malDiv.style.display = 'none';
    thankDiv.style.display = 'block';
  
    httpGetAsync(url, function() {
  
    });
  });
}

document.addEventListener('DOMContentLoaded', function () {
  var div = document.getElementById("malicious");
  div.addEventListener('click', reportMalicious);
});