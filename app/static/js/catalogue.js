
$(".service-descr").dotdotdot({
        ellipsis: ' [...] ',
        wrap: 'word',
        after: "a.read_more",
        watch: true,
        height: 70,
        callback: function(isTruncated, orgContent) {
            if (isTruncated == true) {
                //$(".read_more").css("visibility","visible");
            } else {
                $(this).parent().find('.read_more').css("display", "none");
                //$(".read_more").css("display","none");
            }
        }
 });

function cardFilter() {
        var input, filter, cards, cardContainer, h5, title, i;
        input = document.getElementById("cardFilter");
        filter = input.value.toUpperCase();
        cardContainer = document.getElementById("cardsContainer");
        cards = cardContainer.getElementsByClassName("card");
        for (i = 0; i < cards.length; i++) {
            title = cards[i].querySelector(".card-body .card-title");
            if (title.innerText.toUpperCase().indexOf(filter) > -1) {
                cards[i].style.display = "";
            } else {
                cards[i].style.display = "none";
            }
        }
 };

$(document).ready(function() {
        $(".card-img-overlay").hide();
        $(".card").hover(function() {
            $(this).addClass('shadow-lg').css('cursor', 'pointer');
            $(this).find('.card-img-overlay').show();
        }, function() {
            $(this).removeClass('shadow-lg');
            $(this).find('.card-img-overlay').hide();
        });
 });

$(document).ready(function() {
     $('[data-toggle="popover"]').popover();
});