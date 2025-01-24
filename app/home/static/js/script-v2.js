/* ON PAGE LOAD */
$( document ).ready(() => {
    set_loading(false);

    add_loading_on_redirect();
    add_navbar_dropdown_toggle();
    add_navbar_mobile_toggle();
    add_role_dropdown_hover();
    add_service_info_details();
    add_cards_input_filter();
    add_max_length_counter();
    add_max_file_length();
    bookmark_show_on_load();
    bookmark_add_on_click();
});


/* 
*
*   TOGGLE NAVBAR DROPDOWNS 
*
*/

function add_navbar_dropdown_toggle() {
    let dropdowns = $('.navbar-left-dropdown')
    
    dropdowns.each((i, e) => {
        let dropdown = $(e.children[0]);
        let link = $(e.children[1]);
    
        dropdown.on('click', () => {
            let icon = $(dropdown[0].children[1].children[0])
            
            if(icon.css('transform').toString() == 'none') {
                open_popup_menu(e)
            } else {
                close_dropdown_menu(e)
            }
    
            dropdowns.each((i, e) => {
                let otherLink = $(e.children[1]);
                
                if(!link.is(otherLink)) {
                    close_dropdown_menu(e);
                }
            })
        })
    })
    
    function open_popup_menu(e) {
        let dropdown = $(e.children[0]);
        let link = $(e.children[1]);
        let icon = $(dropdown[0].children[1].children[0]);
    
        icon.css('transform', 'rotate(180deg)')
        link.slideDown();
    }
    
    function close_dropdown_menu(e) {
        let dropdown = $(e.children[0]);
        let link = $(e.children[1]);
        let icon = $(dropdown[0].children[1].children[0]);
    
        icon.css('transform', 'none')
        link.slideUp();
    }
}


/* 
*
*   TOGGLE ROLE SELECTION MENU ON HOVER
*
*/

function add_role_dropdown_hover() {
    $('.navbar-left-user-profile-role')
        .on( "mouseenter", () => {
            $('.navbar-left-user-profile-role-dropdown-menu-container').show()
            $('.navbar-left-user-profile-role > .navbar-left-dropdown-parent-icon > i').css('transform', 'rotate(180deg)')
        })
        .on( "mouseleave", () => {
            $('.navbar-left-user-profile-role-dropdown-menu-container').hide()
            $('.navbar-left-user-profile-role > .navbar-left-dropdown-parent-icon > i').css('transform', 'none')
        });
}


/* 
*
*   TOGGLE NAVBAR MENU ON MOBILE
*
*/

function add_navbar_mobile_toggle() {
    let nav_toggle_button = $('.navbar-left-header-mobile-toggle');
    
    nav_toggle_button.on('click', () => {
        let bars = $('.navbar-left-header-mobile-toggle > .fas.fa-bars');
        let times = $('.navbar-left-header-mobile-toggle > .fas.fa-times');
    
        if(times.css('display').toString() === 'none') {
            bars.hide();
            times.show();
    
            $('.navbar-left-dropdowns-container').show();
            $('.navbar-left-bottom').show();
            $('.navbar-left').css('height', '100%');
        } else {
            times.hide();
            bars.show();
            
            $('.navbar-left-dropdowns-container').hide();
            $('.navbar-left-bottom').hide();
            $('.navbar-left').css('height', 'auto');
        }
    })
}


/* 
*
*   SHOW SERVICE INFO DETAILS
*
*/

function add_service_info_details() {
    let cards = $('.dashboard-card');
    let close_buttons = $('.dashboard-card-info-close');
    let info_blurred_bg = $('.dashboard-card-info-container');
    
    cards.on('click', (e) => {
        if(!e.target.classList.contains('exclude-detail-opening')) {
            let id = e.currentTarget.id.split('_').pop();
            let elementName = e.currentTarget.id.split('_')[0];
    
            showCardInfo(id, true, elementName);
        }
    })
    
    close_buttons.on('click', (e) => {
        let id = e.currentTarget.id.split('_').pop();
        let elementName = e.currentTarget.id.split('_')[0];
        showCardInfo(id, false, elementName);
    });
    
    info_blurred_bg.on('click', (e) => {
        if(e.target.classList.contains('dashboard-card-info-container')) {
            let id = e.currentTarget.id.split('_').pop();
            let elementName = e.currentTarget.id.split('_')[0];
            showCardInfo(id, false, elementName);
        }    
    })
    
    function showCardInfo(id, show = true, elementName) {
        let info_detail = $('#' + elementName + '_Info_'+ id);
    
        if(show) {
            info_detail.fadeIn('fast', 'swing')
        } else {
            info_detail.fadeOut('fast', 'swing');
        }
    }
}


/* 
*
*   CARD FILTER
*
*/

function add_cards_input_filter() {
    let input = $('#inputCardFilter');
    let cards = $('.dashboard-card');
    
    input.on('keyup', () => {
        let fadeTime = 300;
        let val = input.val().toUpperCase();
    
        let centralised_count = 0;
        let on_demand_count = 0;
        
        for(let i = 0; i < cards.length; i++) {
            let card = $(cards[i]);
            let title = card.find('.dashboard-card-title').text().toUpperCase();
            let type = card.attr('id').split('_')[0];
    
            if(title.indexOf(val) == -1 && val !== "") {
                card.fadeOut(fadeTime);
            } else {
                card.fadeIn(fadeTime);
    
                if(type == 'dashboardCard') {
                    centralised_count++;
                } else {
                    on_demand_count++;
                }
            }
        }
    
        if($('#dashboardCardsNoResult_1').length > 0) {
            if(centralised_count == 0) {
                $('#dashboardCardsNoResult_1').fadeIn(fadeTime)
            } else {
                $('#dashboardCardsNoResult_1').fadeOut(fadeTime)
            }
        }
    
        if($('#dashboardCardsNoResult_2').length > 0) {
            if(on_demand_count == 0) {
                $('#dashboardCardsNoResult_2').fadeIn(fadeTime)
            } else {
                $('#dashboardCardsNoResult_2').fadeOut(fadeTime)
            }
        }
    })
}


/*
*
* -- LOADING --
*
*/

function add_loading_on_redirect() {
    $('a').click((e) => {
        let link_redirect = $(e.currentTarget).attr('href');

        if(link_redirect == null || link_redirect == undefined) {
            link_redirect = $(e.currentTarget).attr('data-target');
        }

        if(link_redirect == null || link_redirect == undefined) {
            link_redirect = '/';
        }

        // loading if not ID to a section
        if(link_redirect.charAt(0) != '#') {
            // remove loading for external link
            if(this.origin !== window.location.origin || $(e.currentTarget).attr('target') == '_blank') {
                set_loading(false);
            } else {
                set_loading(true, 'You are being redirected to the requested page.<br>Wait on this page without reloading.');
            }
        } 
    });

    // remove loading when page loaded
    $(window).bind("pageshow", (event) => {
        set_loading(false)
    });
}
    
function set_loading(state = true, title = false) {
    let element = $('.dashboard-loading-container');
    let elementTitle = $('.dashboard-loading-title');

    if(typeof title == 'string') {
        if(title !== '') {
            elementTitle.html(title)
        }
    } else {
        elementTitle.html('Your request is being processed.<br>Wait on this page without reloading.')
    }

    if(state) {
        element.show();
    } else {
        element.hide();
    }
}


/*
*
*   -- ALERT --
*
*/

function alert_message(type = 'success', message = 'Success!', icon = '', time = 2000) {
    if(icon == '') {
        switch(type) {
            case 'success':
                icon = '<i class="far fa-check-circle"></i>';
            break;
            
            case 'danger':
                icon = '<i class="far fa-times-circle"></i>';
            break;
        }
    }

    $('#dashboard_alert_message > div').html(icon + message)
    $('#dashboard_alert_message > div').removeClass()
    $('#dashboard_alert_message > div').addClass('alert alert-'+ type)

    $('#dashboard_alert_message').animate({
        right: 40,
        opacity: 1
    });

    setTimeout(() => {
        $('#dashboard_alert_message').animate({
            right: -100,
            opacity: 0
        });
    }, time)
}


/* 
*
*   -- MAX LENGTH COUNTER --
*
*/

function add_max_length_counter() {
    let inputGroup = $("[maxlength]").parent();

    for (const element of inputGroup) {
        const label = $($(element).children()[0]);
        const input = $($(element).children()[1]);

        const maxLength = input.attr('maxlength');
        const text = label.text();
        let chars = input.val().length;

        label.text(`${text} (${chars}/${maxLength})`)

        input.on('input change summernote.change', (e, content) => {
            chars = input.val().length;

            if (e.type === 'summernote') {
                chars = $('<div>').html(content).text().length
            }

            label.text(`${text} (${chars}/${maxLength})`)
        });
    }
}


/* 
*
*   -- MAX SIZE --
*
*/

function add_max_file_length() {
    for(let i = 0; i < $('[maxsize]').length; i++) {
        $($('[maxsize')[i]).on('change', (e) => {
            if(e.currentTarget.files.length > 0) {
                if(e.currentTarget.files[0].size > $($('[maxsize')[i]).attr('maxsize')) {
                    $('[maxsize')[i].parentElement.lastElementChild.innerHTML = '';
                    $('[maxsize')[i].value = '';
                    alert_message('danger', 'The selected file exceeds the allowed size. Impossible to proceed.', '', 5000)
                }
            }
        })
    }
}


/*
*
*   -- DASHBOARD BOOKMARKS --
*
*/

function bookmark_show_on_load() {
    let visible = 0;

    for(let i = 0; i < localStorage.length; i++) {
        if(localStorage.key(i).includes('_bookmark_visibility')) {
            let name = localStorage.key(i).replace('_bookmark_visibility', '');
            let btn = $('[bookmark="'+ name +'"]');
            let icon = $('[bookmark="'+ name +'"] > i');
            let title = btn.prop('title');
            
            if(btn.length > 0) {
                if(localStorage.getItem(localStorage.key(i)) == 1) {
                    visible++;
    
                    $('#'+ name +'_shortcut').show();
            
                    icon.removeClass('far');
                    icon.addClass('fas');
    
                    btn.prop('title', title.replace('Add', 'Remove').replace('to bookmarks', 'from bookmarks'))
                } else {
                    icon.removeClass('fas');
                    icon.addClass('far');
    
                    btn.prop('title', title.replace('Remove', 'Add').replace('from bookmarks', 'to bookmarks'))
                }
            }
        }

        if(i == localStorage.length - 1) {
            if(visible > 0) {
                $('#bookmarks_title').show();
            } else {
                $('#bookmarks_title').fadeOut();
            }
        }
    }
}

function bookmark_add_on_click() {
    let bookmarks = $('.dashboard-card-bookmark')

    bookmarks.on('click', (e) => {
        let name = e.currentTarget.getAttribute('bookmark');
        let storageItem = name + '_bookmark_visibility'
        let btn = $('[bookmark="'+ name +'"]');
        let icon = $('[bookmark="'+ name +'"] > i');
        let title = btn.prop('title');

        if(localStorage[storageItem] == undefined || localStorage[storageItem] == 0) {
            localStorage[storageItem] = 1
            
            icon.removeClass('far');
            icon.addClass('fas');
            btn.prop('title', title.replace('Add', 'Remove').replace('to bookmarks', 'from bookmarks'))

            $('#'+ name +'_shortcut').fadeIn();
        } else {
            localStorage[storageItem] = 0

            icon.removeClass('fas');
            icon.addClass('far');
            btn.prop('title', title.replace('Remove', 'Add').replace('from bookmarks', 'to bookmarks'))

            $('#'+ name +'_shortcut').fadeOut();
        }   
        
        bookmark_show_on_load();
    })
}