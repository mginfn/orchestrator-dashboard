
function hideOrShow(el) {
  var fname = hideOrShow.name.toLowerCase();
  var selector = $(el).data(fname + '-selector');
  var search_id = '[' + selector + ']';

  var pattern = $(el).data(fname + '-' + el.value.toString() + '-pattern');
  var re = new RegExp(pattern);

  $(search_id).each(function () {
    if (this.id !== el.id){
      $(this).parent().closest('div').attr('hidden', true);

      if ( re.test(this.id) ) {
        $(this).parent().closest('div').attr('hidden', false);
      }
    }
  });
};