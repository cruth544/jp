require( 'index.html' )
require( 'css/main.scss' );

(function () {
	var gondola = document.getElementById( 'gondola' );
	var mountains = document.getElementsByClassName( 'mountain' );
	window.addEventListener( 'load', function ( e ) {
		window.scrollTo( 0, Number.MAX_VALUE )
		document.getElementsByTagName( 'main' )[0].className = 'fade-in'

	})











	window.addEventListener( 'beforeunload', function ( e ) {
		window.scrollTo( 0, Number.MAX_VALUE )
	})
})()
