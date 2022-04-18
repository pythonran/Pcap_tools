/**
 * Created by Administrator on 2016/11/1 0001.
 */
/*删除sql*/
$(document.getElementsByName("delsqlbugs")).click(function () {
    if ($(this).hasClass("checked")) {
        $(this).removeClass("checked");
    } else {
        $(this).addClass("checked");
    }
});
$(function () {
    $("#delsql-button").click(deletesqlbugs);
});
function deletesqlbugs() {
    var array = new Array();
    $(document.getElementsByName("delsqlbugs")).each(function () {
        if ($(this).hasClass("checked")) {
            array.push($(this).attr("value"));
            console.log(array);
        }
    });
    $.get("/delbugs/" + array + '/', function (result) {
        if (result.status = 1) {
            window.location.reload();
        } else {
            // alert(result.msg);
        }
    });
}

/*删除xss*/
$(document.getElementsByName("delxssbugs")).click(function () {
    if ($(this).hasClass("checked")) {
        $(this).removeClass("checked");
    } else {
        $(this).addClass("checked");
    }
});
$(function () {
    $("#delxss-button").click(deletexssbugs);
});
function deletexssbugs() {
    var array = new Array();
    $(document.getElementsByName("delxssbugs")).each(function () {
        if ($(this).hasClass("checked")) {
            array.push($(this).attr("value"));
            console.log(array);
        }
    });
    $.get("/delbugs/" + array + '/', function (result) {
        if (result.status = 1) {
            window.location.reload();
        } else {
            // alert(result.msg);
        }
    });
}

/*删除other*/
$(document.getElementsByName("delotherbugs")).click(function () {
    if ($(this).hasClass("checked")) {
        $(this).removeClass("checked");
    } else {
        $(this).addClass("checked");
    }
});
$(function () {
    $("#delother-button").click(deleteotherbugs);
});
function deleteotherbugs() {
    var array = new Array();
    $(document.getElementsByName("delotherbugs")).each(function () {
        if ($(this).hasClass("checked")) {
            array.push($(this).attr("value"));
            console.log(array);
        }
    });
    $.get("/delbugs/" + array + '/', function (result) {
        if (result.status = 1) {
            window.location.reload();
        } else {
            // alert(result.msg);
        }
    });
}

/*删除项目*/
$(document.getElementsByName("delpro")).click(function () {
    if ($(this).hasClass("checked")) {
        $(this).removeClass("checked");
    } else {
        $(this).addClass("checked");
    }
    event.stopPropagation();
});

/*删除嗅探项目*/
$(function () {
    $("#delpro-button").click(deletepro);
});

function deletepro() {
    var array = new Array();
    $(document.getElementsByName("delpro")).each(function () {
        if ($(this).hasClass("checked")) {
            array.push($(this).attr("value"));
            // console.log(array);
        }
    });
    $.get("/delpro/" + array + '/', function (result) {
        if (result.status = 1) {
            window.location.reload();
        } else {
            // alert(result.msg);
        }
    });
}

/*刷新嗅探项目*/
$(function () {
    $("#flush-button").click(flushpro);
});

function flushpro() {
    var array = new Array();
    $("#flushtb tr").each(function () {
        var flag = $(this).children().eq(6).html();
        if (flag == "On") {
            // alert("ON");
            array.push($(this).children().eq(0).attr("value"));
        }
    });
    if (array.length != 0) {
        $.get("/flushsniff/" + array + '/', function (result) {
            if (result.status = 1) {
                layer.msg( '刷新完成', {
                    time: 2000 //1s后自动关闭
                });
                window.location.reload();
            } else {

            }
        });

    }
    else {
        layer.msg("没有正在嗅探中的项目")
    }

}



