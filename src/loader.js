s = document.createElement("script");
s.src = chrome.extension.getURL("src/classifier.js");

s.onload = function(){
  this.remove();
}
document.head.appendChild(s);
