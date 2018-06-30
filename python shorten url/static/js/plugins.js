$(document).ready(function(){
    $(".do").click(function(){
        $(".in_menu").slideToggle(500).css("display","block");
    });
});

$(document).ready(function(){
    $(".me").click(function(){
        $(".in_menu").slideUp(1000).css("display","none");
    });
});
