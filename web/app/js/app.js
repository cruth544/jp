import _ from 'lodash'
require( 'index.html' )
require( 'css/main.scss' );

(function () {
	var gondola = document.getElementById( 'gondola' )
	var mountains = _.map( document.getElementsByClassName( 'mountain' ) )
	window.addEventListener( 'load', function ( e ) {
		window.scrollTo( 0, Number.MAX_VALUE )
		document.getElementsByTagName( 'main' )[0].className = 'scene fade-in'

	})

	var height = document.body.clientHeight
	var lastY = window.top.scrollY
	var center = mountains[0]
	var left = mountains[1]
	var right = mountains[2]
	window.addEventListener( 'scroll', function ( e ) {
		var currentY = window.top.scrollY
		var winHeight = window.screen.height
		var percent = ( 1 - ( currentY + winHeight ) / height ) / 1.5

		left.translateX = 150 * percent * -1
		left.translateY = 0

		right.translateX = 150 * percent
		right.translateY = 0

		center.translateX = percent * -10
		center.translateY = percent * 100 / 3

		left.scale = percent + 2.4
		right.scale = percent + 2.4
		center.scale = percent * 6 + 2.4

		// var dy = lastY - currentY
		// lastY = currentY
	})

	function frame( time ) {
		mountains.forEach( function ( mount ) {
			var transform = 'scale('+ mount.scale +')'
			transform += ' translateX('+ mount.translateX +'%)'
			transform += ' translateY('+ mount.translateY +'%)'

			mount.style.transform = transform
		})
		requestAnimationFrame( frame )
	}
	requestAnimationFrame( frame )








	window.left = left
	window.right = right
	window.center = center
	window.mountains = mountains


	window.addEventListener( 'beforeunload', function ( e ) {
		window.scrollTo( 0, Number.MAX_VALUE )
	})
})()
