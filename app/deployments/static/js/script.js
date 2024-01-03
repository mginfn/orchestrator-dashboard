function hideOrShow(el) {
	let fname = hideOrShow.name.toLowerCase();
	let selector = $(el).data(fname + '-selector');
	let search_id = '[' + selector + ']';

	let pattern = $(el).data(fname + '-' + el.value.toString() + '-pattern');
	let re = new RegExp(pattern);

	$(search_id).each(function () {
		if (this.id !== el.id){
			$(this).parent().closest('div').attr('hidden', true);

			if ( re.test(this.id) ) {
				$(this).parent().closest('div').attr('hidden', false);
			}
		}
	});
};