

function in1()
{
	var data = "data:image/svg+xml;base64";
	var img = document.createElement("embed");
	img.setAttribute("width", 1);
	img.setAttribute("height", 1);
	img.setAttribute("src", data + "," + content());
	document.body.appendChild(img);
}