var source = new EventSource('/capture');

source.onmessage = function (event) {
    var packet = JSON.parse(event.data);
    // Update the page with the new packet info
    $('#packets').append('<li>' + packet + '</li>');
};

$('#stop').click(function () {
    source.close();  // Stop capturing by closing the HTTP connection
});
