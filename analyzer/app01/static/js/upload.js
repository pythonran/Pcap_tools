$(document).ready(function () {

    $('select.dropdown').dropdown();
    $('.ui.checkbox').checkbox();
    $('#delete-button').on('click', function () {
        $('.small.del.modal').modal({
            closable: true,
            allowMultiple: false,
            onDeny: function () {
                return true;
            },
            onApprove: function () {
                var delCheckbox = $("input[name='checkoption']:checked");
                var size = delCheckbox.size();
                if (size > 0) {
                    var params = "";
                    for (var i = 0; i < size; i++) {
                        params += delCheckbox.eq(i).val();
                        if (i != size - 1) {
                            params = params + ',';
                        }
                    }
                    $.post("/delete/" + params + '/', '', function (d) {
                        history.go(0);
                    }, 'text');
                }
            }
        }).modal('show');
    });


    $('#start-button').on('click', function () {

        $.get('/start_sniffer/');
    });


    $('#stop-button').on('click', function () {
        $.get('/stop_sniffer/');
    });


    
    $('#analyze-button').on('click', function () {
        var delCheckbox = $("input[name='checkoption']:checked");
        var size = delCheckbox.size();
        if (size == 1) {
            var params = "";
            for (var i = 0; i < size; i++) {
                param = delCheckbox.eq(i).val();
                window.open('/analyze/' + param + '/' + '1/');
            }
        }else if (size > 1){
            layer.msg("一次只能查看一个文件哦!");
        }else{}
    });

     $('#scan-button').on('click', function () {
        var delCheckbox = $("input[name='checkoption']:checked");
        var size = delCheckbox.size();
        if (size == 1) {
            var params = "";
            for (var i = 0; i < size; i++) {
                param = delCheckbox.eq(i).val();
		urlstr='/scan/' + param + '/';
		alert(urlstr);
                window.open(urlstr);
            }
        }else if(size > 1){
            layer.msg("一次只能扫描一个文件哦!");
        }else{}
    });

    $('#fileupload').fileupload({
        url: '/upload' + '/',
        add: function (e, data) {
            var goUpload = true;
            var uploadFile = data.files[0];
            if (!(/\.(pcap)$/i).test(uploadFile.name)) {
                alert('Pcap file only!');
                goUpload = false;
            }
            
            // if (uploadFile.size > 30000000) { // 2mb
            //     alert('Max Size is 30 MB!');
            //     goUpload = false;
            // }
            if (goUpload == true) {
                data.submit();
            }
        },
        progressall: function (e, data) {
            $('.progress').progress({percent: 1});
            var progressbar = parseInt(data.loaded / data.total * 100, 10);
         
            $('.progress').progress({percent: progressbar});
        },
        done: function (e, data) {
            if (data['textStatus'] == "success")
                $("#progresslabel").append("Upload OK!");
            $('#fileupload').attr({"disabled": "disabled"});
            $('.small.ok.modal').modal('show');
            history.go(0);
        },
    });

});
